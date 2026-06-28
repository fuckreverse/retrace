#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "core/instruction_decoder.h"
#include "io/code_table.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <fmt/format.h>
#include <sstream>
#include <cstring>

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
    size_t total = 4 + 4 + 4 + 4;  // magic, version, canvas_width, canvas_height
    total += 8;                     // num_blocks
    total += res.block_layouts.size() * (8 + 4 + 4 + 4 + 4);  // pc, x,y,w,h
    total += 8;                     // num_edges
    for (const auto& e : res.edge_layouts) {
        total += 8 + 8 + 4;         // from_block, to_block, arrow
        total += 8 + e.polyline.size() * (4 + 4);  // num_points + (fx,fy)*N
    }
    total += 4 + res.dot.size();
    total += 4 + res.dot_annotated.size();

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_s32 = [&](int32_t  v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };
    auto write_f32 = [&](float    v) { std::memcpy(p, &v, 4); p += 4; };

    write_u32(CFLY_BLOB_MAGIC);
    write_u32(CFLY_BLOB_VERSION);
    write_s32(res.canvas_width);
    write_s32(res.canvas_height);

    write_u64(static_cast<uint64_t>(res.block_layouts.size()));
    for (const auto& [pc, bl] : res.block_layouts) {
        write_u64(pc);
        write_s32(bl.x);
        write_s32(bl.y);
        write_s32(bl.width);
        write_s32(bl.height);
    }

    write_u64(static_cast<uint64_t>(res.edge_layouts.size()));
    for (const auto& el : res.edge_layouts) {
        write_u64(el.from_block);
        write_u64(el.to_block);
        write_u32(static_cast<uint32_t>(el.arrow));
        write_u64(static_cast<uint64_t>(el.polyline.size()));
        for (const auto& pt : el.polyline) {
            write_f32(pt.x);
            write_f32(pt.y);
        }
    }

    write_u32(static_cast<uint32_t>(res.dot.size()));
    std::memcpy(p, res.dot.data(), res.dot.size());
    p += res.dot.size();

    write_u32(static_cast<uint32_t>(res.dot_annotated.size()));
    std::memcpy(p, res.dot_annotated.data(), res.dot_annotated.size());
    p += res.dot_annotated.size();

    return buf;
}

bool cfg_layout_deserialize(const std::string& blob, CFGLayoutResult& out) {
    if (blob.size() < 4 + 4 + 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_s32 = [&]() -> int32_t  { int32_t  v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_f32 = [&]() -> float    { float    v; std::memcpy(&v, p, 4); p += 4; return v; };

    if (read_u32() != CFLY_BLOB_MAGIC)   return false;
    if (read_u32() != CFLY_BLOB_VERSION) return false;

    out.canvas_width  = read_s32();
    out.canvas_height = read_s32();

    uint64_t n_blocks = read_u64();
    for (uint64_t i = 0; i < n_blocks; i++) {
        if (p + 8 + 4*4 > end) return false;
        uint64_t pc = read_u64();
        BlockLayout bl;
        bl.x      = read_s32();
        bl.y      = read_s32();
        bl.width  = read_s32();
        bl.height = read_s32();
        out.block_layouts[pc] = bl;
    }

    if (p + 8 > end) return false;
    uint64_t n_edges = read_u64();
    out.edge_layouts.reserve(static_cast<size_t>(n_edges));
    for (uint64_t i = 0; i < n_edges; i++) {
        if (p + 8 + 8 + 4 + 8 > end) return false;
        EdgeLayout el;
        el.from_block = read_u64();
        el.to_block   = read_u64();
        el.arrow      = static_cast<GraphEdge::ArrowDirection>(read_u32());
        uint64_t n_pts = read_u64();
        if (p + n_pts * 8 > end) return false;
        el.polyline.resize(static_cast<size_t>(n_pts));
        for (uint64_t j = 0; j < n_pts; j++) {
            el.polyline[j].x = read_f32();
            el.polyline[j].y = read_f32();
        }
        out.edge_layouts.push_back(std::move(el));
    }

    if (p + 4 > end) return false;
    uint32_t dot_len = read_u32();
    if (p + dot_len > end) return false;
    out.dot.assign(p, dot_len);
    p += dot_len;

    if (p + 4 > end) return false;
    uint32_t dot_ann_len = read_u32();
    if (p + dot_ann_len > end) return false;
    out.dot_annotated.assign(p, dot_ann_len);
    p += dot_ann_len;

    return true;
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

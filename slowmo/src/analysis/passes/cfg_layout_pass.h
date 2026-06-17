#pragma once

#include "analysis/pass_manager.h"
#include "analysis/passes/GraphGridLayout.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace tenet {

// Forward declarations
class InstructionDecoder;
class CodeTable;
struct CFGResult;

// ─── Computed block layout ─────────────────────────────────────────────────

/// Pixel-space position and size of a basic block, produced by GraphGridLayout.
struct BlockLayout {
    int x      = 0;  ///< Left edge in pixels
    int y      = 0;  ///< Top edge in pixels
    int width  = 0;  ///< Width in pixels
    int height = 0;  ///< Height in pixels
};

/// A single edge polyline: a sequence of 2-D points describing the routed path.
using EdgePolyline = std::vector<Vec2f>;

/// Computed layout for one directed CFG edge.
struct EdgeLayout {
    uint64_t     from_block;  ///< start_pc of source block
    uint64_t     to_block;    ///< start_pc of target block
    EdgePolyline polyline;    ///< Pixel-space waypoints (from block bottom to target top)
    GraphEdge::ArrowDirection arrow = GraphEdge::ArrowDirection::Down;
};

/// Full result of the grid-layout pass:
/// - pixel coordinates for every basic block
/// - routed polylines for every edge
/// - total canvas dimensions
struct CFGLayoutResult {
    // ─── Grid layout result (coordinates) ──────────────────────────────

    /// Pixel-space layout for each block, keyed by block start_pc.
    std::map<uint64_t, BlockLayout> block_layouts;

    /// Routed edge polylines.
    std::vector<EdgeLayout> edge_layouts;

    /// Total canvas width in pixels (0 if layout not computed).
    int canvas_width  = 0;

    /// Total canvas height in pixels (0 if layout not computed).
    int canvas_height = 0;

    // ─── DOT fallback (legacy / export) ────────────────────────────────

    /// Simple DOT output: nodes labeled with start_pc, edges with taken_count.
    /// Kept for export / debugging purposes.
    std::string dot;

    /// Annotated DOT output with full disassembly in each node.
    std::string dot_annotated;

    // ─── Metadata ───────────────────────────────────────────────────────

    size_t node_count() const { return block_layouts.size(); }
};

// ─── CFG layout pass ───────────────────────────────────────────────────────

/// Computes a structured (non-Graphviz) CFG layout using GraphGridLayout,
/// which implements a custom hierarchical/grid placement algorithm
/// similar to Ghidra's decompiler layout.
///
/// Also generates DOT strings for debugging / export.
///
/// Dependencies: "cfg"
/// Result type:  CFGLayoutResult
class CFGLayoutPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "cfg_layout"; }
    std::string_view description() const override {
        return "Compute structured CFG layout (GraphGridLayout) + DOT export";
    }

    std::vector<std::string_view> dependencies() const override {
        return { "cfg" };
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 2.0f; }

    // ─── Layout configuration ──────────────────────────────────────────

    /// Default estimated block dimensions used when no font metrics available.
    /// These can be changed before the pass runs.
    int default_block_width  = 200;
    int default_block_height = 24;    // per-instruction line height
    int insn_height          = 14;    // px per instruction line

    GraphGridLayout::LayoutType layout_type = GraphGridLayout::LayoutType::Medium;
};

// ─── Free DOT generation helpers ──────────────────────────────────────────

/// Generate a simple DOT string with nodes and edges.
std::string generate_dot(const CFGResult& cfg);

/// Generate an annotated DOT with full disassembly in each node box.
std::string generate_dot_annotated(
    const CFGResult& cfg,
    InstructionDecoder& decoder,
    const CodeTable& code_table);

}  // namespace tenet

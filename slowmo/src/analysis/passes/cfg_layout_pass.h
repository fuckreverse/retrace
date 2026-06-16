#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace tenet {

// Forward declarations
class InstructionDecoder;
class CodeTable;
struct CFGResult;

// ─── CFG DOT result ──────────────────────────────────────────────────────

/// Result of CFG layout pass: DOT source strings ready for Graphviz rendering.
/// This pass does NOT compute coordinates — it delegates layout to `dot` (Graphviz).
struct CFGLayoutResult {
    /// Simple DOT output: nodes labeled with start_pc, edges with taken_count.
    std::string dot;

    /// Annotated DOT output: nodes contain full disassembly, edges styled
    /// (dashed for calls, gray for fallthrough).
    std::string dot_annotated;

    /// Number of basic blocks in the CFG.
    size_t node_count() const { return node_count_; }

    size_t node_count_ = 0;
};

// ─── CFG layout pass ─────────────────────────────────────────────────────

/// Generates DOT (Graphviz) representations of the CFG.
/// Layout is delegated entirely to Graphviz's `dot` engine.
/// Dependencies: "cfg" (for CFGResult)
/// Result type: CFGLayoutResult
class CFGLayoutPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "cfg_layout"; }
    std::string_view description() const override {
        return "Generate Graphviz DOT for CFG (layout delegated to dot)";
    }

    std::vector<std::string_view> dependencies() const override {
        return { "cfg" };
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 2.0f; }
};

// ─── Free DOT generation functions ────────────────────────────────────────

/// Generate a simple DOT string with nodes and edges.
/// Nodes are labeled with block start PCs; edges annotated with taken_count.
std::string generate_dot(const CFGResult& cfg);

/// Generate an annotated DOT with full disassembly in each node box.
/// Call edges are rendered with style=dashed; fallthrough edges in gray.
std::string generate_dot_annotated(
    const CFGResult& cfg,
    InstructionDecoder& decoder,
    const CodeTable& code_table);

}  // namespace tenet

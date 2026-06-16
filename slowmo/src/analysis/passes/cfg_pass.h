#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace tenet {

// ─── CFG pass result types ────────────────────────────────────────────────

/// How a basic block terminates.
enum class TerminatorKind : uint8_t {
    Fallthrough,       // Non-branch, flows into the next block
    Branch,            // Unconditional branch (b)
    ConditionalBranch, // Conditional branch (b.cond, cbz, cbnz, tbz, tbnz)
    Call,              // Call (bl / blr)
    Return,            // Return (ret)
    IndirectBranch,    // Indirect branch (br)
};

/// A basic block in the CFG.
struct BasicBlock {
    uint64_t start_pc;                     // First PC in this block
    uint64_t end_pc;                       // Last PC in this block (inclusive)
    std::vector<uint64_t> instructions;     // All PCs in this block, in order
    uint64_t execution_count = 0;           // Sum of execution counts across all PCs
    TerminatorKind terminator = TerminatorKind::Fallthrough;
};

/// A directed edge in the CFG between two basic blocks.
struct CFGEdge {
    uint64_t from_block;   // start_pc of the source block
    uint64_t to_block;     // start_pc of the destination block
    uint64_t taken_count;  // How many times this edge was taken in the trace
    bool is_fallthrough;   // True if this is a fallthrough edge (not an explicit branch)
};

/// Result of CFG analysis.
struct CFGResult {
    /// Basic blocks indexed by their start_pc.
    std::map<uint64_t, BasicBlock> blocks;

    /// All edges in the CFG.
    std::vector<CFGEdge> edges;

    // ─── Query helpers ──────────────────────────────────────────────────

    /// Find the basic block that contains the given PC.
    /// Returns nullptr if no block contains this PC.
    const BasicBlock* block_containing(uint64_t pc) const {
        // Use upper_bound to find the first block starting after pc,
        // then step back to the previous block which may contain pc.
        auto it = blocks.upper_bound(pc);
        if (it == blocks.begin()) return nullptr;
        --it;
        const auto& block = it->second;
        if (pc >= block.start_pc && pc <= block.end_pc) {
            return &block;
        }
        return nullptr;
    }

    /// Get successor edges of a block (by its start_pc).
    std::vector<const CFGEdge*> successors(uint64_t block_start) const {
        std::vector<const CFGEdge*> result;
        for (const auto& edge : edges) {
            if (edge.from_block == block_start) {
                result.push_back(&edge);
            }
        }
        return result;
    }

    /// Get predecessor edges of a block (by its start_pc).
    std::vector<const CFGEdge*> predecessors(uint64_t block_start) const {
        std::vector<const CFGEdge*> result;
        for (const auto& edge : edges) {
            if (edge.to_block == block_start) {
                result.push_back(&edge);
            }
        }
        return result;
    }

    /// Total number of basic blocks.
    size_t block_count() const { return blocks.size(); }

    /// Total number of edges.
    size_t edge_count() const { return edges.size(); }
};

// ─── CFG pass ─────────────────────────────────────────────────────────────

/// Builds a control flow graph from the trace.
/// Identifies basic blocks by detecting branch targets and branch instructions,
/// then constructs edges by walking the trace.
/// Dependencies: "xref" (for the set of executed PCs)
/// Result type: CFGResult
class CFGPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "cfg"; }
    std::string_view description() const override {
        return "Build control flow graph from trace";
    }

    std::vector<std::string_view> dependencies() const override {
        return { "xref" };
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 8.0f; }
};

}  // namespace tenet

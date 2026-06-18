#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>
#include <string>

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct CallContextConfig {
    /// Target instruction ID to get context for.
    uint64_t target_inst_id = 0;
    /// Number of instructions before/after to include.
    uint32_t context_before = 10;
    uint32_t context_after = 10;
    /// Maximum call stack depth to reconstruct.
    uint32_t max_stack_depth = 32;
};

// ─── Context entry ─────────────────────────────────────────────────────────

struct ContextInstruction {
    uint64_t inst_id;
    uint64_t pc;
    std::string disassembly;      // Disassembled text
    bool is_target = false;        // Is this the target instruction?
    uint32_t loop_depth = 0;       // Nesting depth at this point
    uint64_t loop_iteration = 0;   // Which iteration of innermost loop
};

struct CallStackFrame {
    uint64_t call_site_pc;         // PC of the BL/BLR instruction
    uint64_t callee_pc;            // PC of the function entry
    uint64_t call_inst_id;         // inst_id of the call instruction
    uint64_t return_addr;          // LR value (expected return address)
};

// ─── Result ────────────────────────────────────────────────────────────────

struct CallContextResult {
    /// Instructions surrounding the target (before + target + after).
    std::vector<ContextInstruction> instructions;

    /// Reconstructed call stack at the target instruction.
    std::vector<CallStackFrame> call_stack;

    /// Loop context: which loops contain the target instruction.
    struct LoopContext {
        uint64_t header_pc;
        uint32_t nesting_depth;
        uint64_t current_iteration;    // Which iteration we're in
        uint64_t total_iterations;     // Total observed iterations
    };
    std::vector<LoopContext> loop_contexts;

    /// Target instruction details.
    uint64_t target_inst_id = 0;
    uint64_t target_pc = 0;
};

// ─── Pass ──────────────────────────────────────────────────────────────────

/// Provides rich context for a given instruction: surrounding instructions,
/// call stack reconstruction, and loop position information.
///
/// Dependencies: "loop" (for loop context), "xref" (for PC resolution).
///
/// Result type: CallContextResult
class CallContextPass final : public AnalysisPass {
public:
    explicit CallContextPass(CallContextConfig cfg = {}) : cfg_(std::move(cfg)) {}

    std::string_view name() const override { return "call_context"; }
    std::string_view description() const override {
        return "Rich context for instruction: call stack + loop position + neighbors";
    }
    std::vector<std::string_view> dependencies() const override {
        return { "loop" };
    }
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 2.0f; }

private:
    CallContextConfig cfg_;

    /// Reconstruct call stack by scanning backwards for BL/BLR + matching returns.
    std::vector<CallStackFrame> reconstruct_call_stack(
        PassContext& ctx, uint64_t target_inst_id);
};

}  // namespace tenet

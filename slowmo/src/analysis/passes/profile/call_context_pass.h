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
};

// ─── Context entry ─────────────────────────────────────────────────────────

struct ContextInstruction {
    uint64_t inst_id;
    uint64_t pc;
    std::string disassembly;      // Disassembled text
    bool is_target = false;        // Is this the target instruction?
    uint32_t loop_depth = 0;       // Nesting depth at this point
};

/// A single frame of the reconstructed call stack, derived from
/// FunctionResult::call_stack_at() (see function_pass.h). Outermost first.
struct CallStackFrame {
    uint64_t call_site_pc;         // PC of the BL/BLR instruction
    uint64_t callee_pc;            // PC of the function entry (target_pc of the call)
    uint64_t call_inst_id;         // inst_id of the call instruction
    uint64_t return_inst_id;       // inst_id of the matching RET (0 if not yet returned)
    bool     is_tail_call = false; // Whether this frame was entered via a tail call
};

// ─── Result ────────────────────────────────────────────────────────────────

struct CallContextResult {
    /// Instructions surrounding the target (before + target + after).
    std::vector<ContextInstruction> instructions;

    /// Reconstructed call stack at the target instruction (outermost first).
    /// Derived from the "function" pass result — see CallContextPass::run().
    std::vector<CallStackFrame> call_stack;

    /// Loop context: which loops contain the target instruction.
    struct LoopContext {
        uint64_t header_pc;
        uint32_t nesting_depth;
        uint64_t total_iterations;     // Total observed iterations of this loop
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
/// This pass is a thin aggregation layer: the call stack is NOT reconstructed
/// independently (that would duplicate "function"'s call/return state
/// machine); instead it is derived from FunctionResult::call_stack_at(),
/// which already performs a well-tested, O(log N), tail-call-aware
/// reconstruction over the whole trace. Loop membership is likewise derived
/// from LoopResult::innermost_loop_at() rather than re-deriving it here.
///
/// Dependencies: "function" (call stack), "loop" (loop context).
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
        return { "function", "loop" };
    }
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 1.0f; }

private:
    CallContextConfig cfg_;
};

}  // namespace tenet

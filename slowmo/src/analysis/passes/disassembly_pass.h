#pragma once

#include "analysis/pass_manager.h"
#include <string>
#include <vector>

namespace tenet {

// ─── Disassembly result for one instruction ───────────────────────────────

struct DisasmEntry {
    uint64_t inst_id;
    uint64_t pc;
    uint64_t static_pc;
    std::string mnemonic;
    std::string op_str;
    std::string full_disasm;
    uint32_t opcode;
    bool is_branch;
    bool is_call;
    bool is_return;
    bool is_load;
    bool is_store;
    bool is_system;
};

// ─── Disassembly pass ─────────────────────────────────────────────────────

/// Produces a disassembly table for all (or a range of) instructions.
/// Result type: std::vector<DisasmEntry>
class DisassemblyPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "disassembly"; }
    std::string_view description() const override {
        return "Disassemble all instructions in the trace range";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 5.0f; }
};

}  // namespace tenet

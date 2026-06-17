#pragma once

#include "analysis/pass_manager.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <cstdint>

namespace tenet {

// ─── Per-PC decoded info (stored once per unique PC) ──────────────────────

struct PCDisasmEntry {
    uint64_t pc         = 0;
    uint64_t static_pc  = 0;   // pc - module_slide
    std::string mnemonic;
    std::string op_str;
    std::string full_disasm;
    uint32_t opcode     = 0;
    bool is_branch      = false;
    bool is_call        = false;
    bool is_return      = false;
    bool is_load        = false;
    bool is_store       = false;
    bool is_system      = false;
    bool valid          = false;  // false → no-code / decode failure
};

// ─── Disassembly result for one instruction (on-demand, cheap to construct) ─

struct DisasmEntry {
    uint64_t inst_id    = 0;
    uint64_t pc         = 0;
    uint64_t static_pc  = 0;
    std::string mnemonic;
    std::string op_str;
    std::string full_disasm;
    uint32_t opcode     = 0;
    bool is_branch      = false;
    bool is_call        = false;
    bool is_return      = false;
    bool is_load        = false;
    bool is_store       = false;
    bool is_system      = false;
};

// ─── DisasmTable: PC-indexed table, supports lazy per-inst lookup ──────────
//
// Instead of materialising one DisasmEntry per instruction (O(trace) memory),
// we store:
//   • pc_table    : PC → PCDisasmEntry  (one entry per *unique* PC executed)
//   • inst_to_pc  : inst_id → PC        (maps each instruction to its PC)
//
// Callers call lookup(inst_id) to get a lightweight DisasmEntry on the fly.
// This reduces memory from O(N_instructions × ~120B) to O(N_unique_PCs × ~120B)
// plus O(N_instructions × 8B) for the inst_to_pc index.

struct DisasmTable {
    // PC → per-PC decoded info (deduped).
    std::unordered_map<uint64_t, PCDisasmEntry> pc_table;

    // inst_id → PC, stored as a flat vector indexed by (inst_id - base_inst_id).
    // base_inst_id is the first inst_id in the range.
    uint64_t base_inst_id = 0;
    std::vector<uint64_t> inst_to_pc;  // inst_to_pc[inst_id - base_inst_id] = pc

    /// Look up a single instruction.  Returns nullopt if inst_id is out of range.
    std::optional<DisasmEntry> lookup(uint64_t inst_id) const {
        if (inst_id < base_inst_id) return std::nullopt;
        size_t idx = inst_id - base_inst_id;
        if (idx >= inst_to_pc.size()) return std::nullopt;

        uint64_t pc = inst_to_pc[idx];

        DisasmEntry e;
        e.inst_id = inst_id;
        e.pc      = pc;

        auto it = pc_table.find(pc);
        if (it != pc_table.end()) {
            const auto& info = it->second;
            e.static_pc  = info.static_pc;
            e.opcode     = info.opcode;
            e.mnemonic   = info.mnemonic;
            e.op_str     = info.op_str;
            e.full_disasm = info.full_disasm;
            e.is_branch  = info.is_branch;
            e.is_call    = info.is_call;
            e.is_return  = info.is_return;
            e.is_load    = info.is_load;
            e.is_store   = info.is_store;
            e.is_system  = info.is_system;
        } else {
            e.full_disasm = "<no code>";
        }
        return e;
    }

    /// Look up only the PC for an inst_id (cheaper than full lookup).
    uint64_t pc_of(uint64_t inst_id) const {
        if (inst_id < base_inst_id) return 0;
        size_t idx = inst_id - base_inst_id;
        if (idx >= inst_to_pc.size()) return 0;
        return inst_to_pc[idx];
    }

    /// Look up the per-PC entry directly.
    const PCDisasmEntry* pc_entry(uint64_t pc) const {
        auto it = pc_table.find(pc);
        return (it != pc_table.end()) ? &it->second : nullptr;
    }

    /// Total number of instructions indexed.
    size_t inst_count() const { return inst_to_pc.size(); }

    /// Number of unique PCs.
    size_t unique_pc_count() const { return pc_table.size(); }
};

// ─── Disassembly pass ─────────────────────────────────────────────────────

/// Builds a DisasmTable for all (or a range of) instructions.
///
/// The result is PC-indexed rather than instruction-indexed, so memory usage
/// scales with the number of *unique* PCs rather than total instructions.
/// Per-instruction DisasmEntry objects can be obtained on-demand via lookup().
///
/// Result type: DisasmTable
class DisassemblyPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "disassembly"; }
    std::string_view description() const override {
        return "Build PC-indexed disassembly table for on-demand instruction lookup";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 1.0f; }  // much cheaper now
};

}  // namespace tenet

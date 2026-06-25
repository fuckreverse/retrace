#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
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

struct DisasmTable {
    // PC → per-PC decoded info (deduped).
    std::unordered_map<uint64_t, PCDisasmEntry> pc_table;

    // inst_id → PC, stored as a flat vector indexed by (inst_id - base_inst_id).
    uint64_t base_inst_id = 0;
    std::vector<uint64_t> inst_to_pc;

    /// Look up a single instruction.
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

    size_t inst_count() const { return inst_to_pc.size(); }
    size_t unique_pc_count() const { return pc_table.size(); }
};

// ─── DisassemblyCollector ─────────────────────────────────────────────────

/// Lightweight collector that records inst_id → PC mapping during a
/// sequential trace scan.  Phase 1 (code_table decode) is done externally
/// in DisassemblyPass::run(); this collector only handles Phase 2.
class DisassemblyCollector final : public TraceCollector {
public:
    explicit DisassemblyCollector(uint64_t base_inst_id, uint64_t expected_count)
        : base_inst_id_(base_inst_id), expected_count_(expected_count) {}

    std::string_view name() const override { return "DisassemblyCollector"; }

    bool begin(uint64_t start_inst_id, uint64_t end_inst_id) override {
        (void)start_inst_id; (void)end_inst_id;
        inst_to_pc_.clear();
        inst_to_pc_.reserve(expected_count_);
        return true;
    }

    void on_inst(uint64_t /*inst_id*/, const InstView& inst) override {
        inst_to_pc_.push_back(inst.pc);
    }

    /// Take the inst_to_pc vector after scan completes.
    std::vector<uint64_t> take_inst_to_pc() { return std::move(inst_to_pc_); }

    uint64_t base_inst_id() const { return base_inst_id_; }

private:
    uint64_t base_inst_id_;
    uint64_t expected_count_;
    std::vector<uint64_t> inst_to_pc_;
};

// ─── Disassembly pass ─────────────────────────────────────────────────────

/// Builds a DisasmTable for all (or a range of) instructions.
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
    float estimated_cost() const override { return 1.0f; }
};

}  // namespace tenet

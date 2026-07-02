#pragma once

// ═══════════════════════════════════════════════════════════════════════════════
// VM Abstract Pass — Virtual Machine dispatcher detection, handler extraction,
// and VM state reconstruction from execution traces.
//
// Designed for LLM-orchestrated analysis: accepts optional static hints from
// IDA (dispatcher PC, handler entries, VM-PC register, opcode format) to
// accelerate and improve analysis.  Falls back to automatic detection when
// no hints are provided.
// ═══════════════════════════════════════════════════════════════════════════════

#include "analysis/pass_manager.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── VM type classification ──────────────────────────────────────────────────

enum class VMArchType : uint8_t {
    Unknown,
    StackMachine,    // Push/pop operands via a VM stack pointer
    RegisterMachine, // Operands stored in VM register file (fixed offsets in ctx)
};

enum class DispatchType : uint8_t {
    Unknown,
    WhileSwitch,       // Classic while(1){switch(opcode){...}}
    IndirectBranch,    // Computed BR Xn via jump table
    CallTable,         // BLR Xn dispatch — handlers return via RET
    ThreadedCode,      // Handler tail-chains to next handler directly
    Trampoline,        // Handlers return to a small "next" trampoline
};

inline const char* vm_arch_name(VMArchType t) {
    switch (t) {
        case VMArchType::Unknown:        return "Unknown";
        case VMArchType::StackMachine:   return "StackMachine";
        case VMArchType::RegisterMachine:return "RegisterMachine";
    }
    return "Unknown";
}

inline const char* dispatch_type_name(DispatchType t) {
    switch (t) {
        case DispatchType::Unknown:        return "Unknown";
        case DispatchType::WhileSwitch:    return "WhileSwitch";
        case DispatchType::IndirectBranch: return "IndirectBranch";
        case DispatchType::CallTable:      return "CallTable";
        case DispatchType::ThreadedCode:   return "ThreadedCode";
        case DispatchType::Trampoline:     return "Trampoline";
    }
    return "Unknown";
}

// ─── Static hints (from IDA / LLM) ──────────────────────────────────────────

/// Hint about the dispatcher location (from static analysis).
struct DispatcherHint {
    uint64_t loop_header_pc = 0;       // PC of the dispatch loop header
    uint64_t indirect_branch_pc = 0;   // PC of the dispatch BR/BLR instruction (optional)
};

/// Hint about which register holds the VM program counter.
struct VMPCHint {
    uint8_t  reg = 0xFF;               // Host register index (0-28); 0xFF = unknown
    uint64_t bytecode_base = 0;        // Base address of bytecode buffer (optional)
};

/// Hint about opcode encoding format.
struct OpcodeFormatHint {
    uint8_t  opcode_size = 0;          // Bytes per opcode (1/2/4); 0 = unknown
    uint64_t opcode_mask = UINT64_MAX;  // Mask applied after load to extract opcode (default: no masking)
    uint8_t  opcode_shift = 0;         // Right shift after masking
};

/// Hint about a VM context structure.
struct VMContextHint {
    uint8_t ctx_base_reg = 0xFF;       // Register holding vm_ctx pointer
    /// Named fields at known offsets.
    struct Field {
        uint32_t    offset;
        std::string name;
    };
    std::vector<Field> fields;
};

// ─── VMConfig ────────────────────────────────────────────────────────────────

/// Configuration for VMAbstractPass.  All hints are optional.
struct VMConfig {
    // ── Auto-detection control ───────────────────────────────────────────
    bool  auto_detect = true;          // When true, auto-detect dispatcher if no hint

    /// Minimum loop iteration count to consider as VM dispatcher candidate.
    uint64_t min_dispatch_iterations = 10;

    /// Minimum number of distinct indirect-branch targets to qualify.
    uint32_t min_handler_count = 3;

    /// Hint about VM architecture type.  When Unknown, the pass infers from
    /// handler memory access patterns (stack-pointer-style vs register-file-style).
    VMArchType arch_type_hint = VMArchType::Unknown;

    // ── Static hints ─────────────────────────────────────────────────────
    std::optional<DispatcherHint>  dispatcher;
    std::vector<uint64_t>          handler_entry_pcs;    // Known handler entry PCs
    std::optional<VMPCHint>        vm_pc;
    std::optional<OpcodeFormatHint> opcode_format;
    std::optional<VMContextHint>   vm_context;

    /// Human-provided handler semantic labels: handler_entry_pc → name.
    /// E.g. {0x5000: "ADD", 0x5100: "LOAD", 0x5200: "BRANCH"}.
    std::map<uint64_t, std::string> handler_names;
};

// ─── Result types ────────────────────────────────────────────────────────────

/// A single handler (VM opcode implementation).
struct VMHandler {
    uint64_t entry_pc = 0;             // First PC of the handler body
    uint64_t exit_pc = 0;              // Last PC before returning to dispatcher
    std::vector<uint64_t> body_pcs;    // All unique PCs in handler body (ordered)
    uint64_t execution_count = 0;      // How many times this handler was dispatched

    /// Opcode value(s) that route to this handler (empty if not decoded).
    std::vector<uint64_t> opcode_values;

    /// Semantic label (from hint or auto-classification).
    std::string label;

    // ── Register effects (observed across executions) ────────────────────
    uint64_t regs_read_mask = 0;       // Bitmask: registers read by handler
    uint64_t regs_written_mask = 0;    // Bitmask: registers written by handler

    // ── Memory effects ──────────────────────────────────────────────────
    uint32_t mem_reads = 0;            // Total memory read operations
    uint32_t mem_writes = 0;           // Total memory write operations
};

/// One step in the VM execution trace (one handler dispatch).
struct VMStep {
    uint64_t inst_id_start = 0;        // First native inst_id of this step
    uint64_t inst_id_end = 0;          // Last native inst_id (inclusive)
    uint64_t handler_entry_pc = 0;     // Which handler was dispatched

    uint64_t opcode_value = 0;         // Decoded opcode (0 if unknown)
    bool     opcode_valid = false;     // Whether opcode_value was successfully decoded

    /// VM-PC value at this step (runtime address of bytecode being read).
    uint64_t vm_pc_value = 0;
    bool     vm_pc_valid = false;

    /// VM context field snapshots at this step (from VMContextHint).
    /// Pairs of (field_name, value) read from the context struct.
    std::vector<std::pair<std::string, uint64_t>> ctx_fields;
};

/// Detected VM dispatcher.
struct VMDispatcher {
    uint64_t loop_header_pc = 0;
    uint64_t indirect_branch_pc = 0;   // The BR/BLR that selects handlers
    uint64_t iteration_count = 0;      // Total dispatch iterations observed
    DispatchType dispatch_type = DispatchType::Unknown;
    float    confidence = 0.0f;        // Detection confidence [0, 1]

    /// Registers that are "live" across dispatch iterations (state registers).
    std::vector<uint8_t> state_regs;

    /// Registers that are invariant across all iterations (base pointers etc).
    std::vector<uint8_t> invariant_regs;
};

/// Top-level result of VM abstract analysis.
struct VMAbstractResult {
    // ── Dispatcher ───────────────────────────────────────────────────────
    VMDispatcher dispatcher;

    // ── Architecture ─────────────────────────────────────────────────────
    VMArchType arch_type = VMArchType::Unknown;

    // ── VM-PC identification ─────────────────────────────────────────────
    uint8_t  vm_pc_reg = 0xFF;         // Host register holding VM-PC (0xFF=unknown)
    uint64_t bytecode_base = 0;        // Inferred bytecode base address
    uint64_t bytecode_end = 0;         // Inferred bytecode end address

    // ── Handlers ─────────────────────────────────────────────────────────
    std::vector<VMHandler> handlers;

    /// Handler lookup by entry_pc.
    ankerl::unordered_dense::map<uint64_t, size_t> handler_by_pc;

    // ── VM execution trace ───────────────────────────────────────────────
    std::vector<VMStep> steps;

    // ── Statistics ───────────────────────────────────────────────────────
    uint64_t total_native_instructions = 0;
    uint64_t total_vm_steps = 0;

    // ── Query helpers ────────────────────────────────────────────────────

    const VMHandler* handler_at(uint64_t entry_pc) const {
        auto it = handler_by_pc.find(entry_pc);
        if (it == handler_by_pc.end()) return nullptr;
        return &handlers[it->second];
    }

    /// Return handlers sorted by execution_count (descending).
    std::vector<const VMHandler*> handlers_by_frequency() const {
        std::vector<const VMHandler*> sorted;
        sorted.reserve(handlers.size());
        for (const auto& h : handlers) sorted.push_back(&h);
        std::sort(sorted.begin(), sorted.end(),
                  [](const VMHandler* a, const VMHandler* b) {
                      return a->execution_count > b->execution_count;
                  });
        return sorted;
    }
};

// ─── Pass class ──────────────────────────────────────────────────────────────

/// Detects VM dispatchers, extracts handler sets, and reconstructs VM execution
/// from an instruction-level trace.
///
/// Dependencies:
///   - "loop" (hard): loop detection for finding dispatch loops
///   - "cfg"  (hard): basic block graph for handler boundary analysis
///   - "xref" (hard): PC→inst_id bitmap for efficient iteration lookup
///
/// Result type: VMAbstractResult
class VMAbstractPass final : public AnalysisPass {
public:
    explicit VMAbstractPass(VMConfig config = {})
        : config_(std::move(config)) {}

    std::string_view name() const override { return "vm_abstract"; }
    std::string_view description() const override {
        return "VM dispatcher detection, handler extraction, and execution abstraction";
    }

    std::vector<std::string_view> dependencies() const override {
        return {"loop", "cfg", "xref"};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 15.0f; }

private:
    VMConfig config_;
};

}  // namespace tenet

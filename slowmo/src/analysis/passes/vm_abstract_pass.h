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
    FetchOnly,         // No handler/opcode modeling — just snapshot VM state
                       // once per fetch cycle. Anchored on EITHER:
                       //   (a) `dispatcher.loop_header_pc` — a single stable
                       //       PC hit exactly once per VM instruction (via
                       //       xref), or
                       //   (b) `dispatcher.mem_anchor_addr` — a memory
                       //       location written exactly once per VM
                       //       instruction (via MemoryModel::write_history),
                       //       for VMs so heavily CFF-obfuscated that NO
                       //       single PC satisfies (a) (the fetch/PC++ logic
                       //       is cloned across many code paths, but always
                       //       targets the same memory field).
                       // For VMs where the handler dispatch itself is
                       // obfuscated beyond recognition (e.g. a CFF-wrapped
                       // binary-search opcode-compare tree with no single
                       // "handler selected" PC), this sidesteps handler
                       // discovery entirely and just answers "what does VM
                       // state look like at each fetch cycle". No loop/CFG
                       // dependency, no handler classification, no opcode
                       // decoding required.
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
        case DispatchType::FetchOnly:      return "FetchOnly";
    }
    return "Unknown";
}

// ─── Static hints (from IDA / LLM) ──────────────────────────────────────────

/// Hint about the dispatcher location (from static analysis).
struct DispatcherHint {
    uint64_t loop_header_pc = 0;       // PC of the dispatch loop header
    uint64_t indirect_branch_pc = 0;   // PC of the dispatch BR/BLR instruction (optional)

    // ── Memory-write anchor (alternative to loop_header_pc) ──────────────
    //
    // Some VMs are obfuscated (e.g. control-flow flattening) to the point
    // where NO single native PC is hit exactly once per VM instruction: the
    // "fetch" logic (e.g. `ldr x8,[ctx,#off]; add x8,x8,#1; str x8,[ctx,#off]`)
    // gets cloned across many CFF-duplicated code paths, so its PC varies
    // from one VM instruction to the next even though it always targets the
    // same memory location (e.g. a VM-PC/instruction-counter field inside a
    // heap-allocated VM context struct).
    //
    // When `mem_anchor_addr` is non-zero, VMAbstractPass (in FetchOnly mode)
    // derives the fetch-cycle inst_id list from `MemoryModel::write_history()`
    // on this address instead of `xref.inst_ids_at(loop_header_pc)`. This
    // sidesteps the "no stable anchor PC" problem entirely: the anchor is a
    // memory location, not code.
    //
    // `mem_anchor_addr` is a **runtime address** (with ASLR slide applied),
    // typically `ctx_base + field_offset` for some fixed field_offset that
    // is stable across runs (the ctx struct itself may be allocated at a
    // different heap address each run, but the field offset within it is
    // stable — resolve mem_anchor_addr at hint-construction time using the
    // observed runtime ctx_base for THIS trace).
    uint64_t mem_anchor_addr = 0;
    uint8_t  mem_anchor_size = 4;      // Byte width of the write to watch for (1/2/4/8)
};

/// Hint about which register holds the VM program counter.
struct VMPCHint {
    uint8_t  reg = 0xFF;               // Host register index (0-28); 0xFF = unknown
    uint64_t bytecode_base = 0;        // Base address of bytecode buffer (optional)
};

/// One step in an opcode deobfuscation pipeline.
/// Applied in order after loading the raw bytes from memory.
///
/// Supported ops:  sub, add, xor, and, or, lsr, lsl, mul, ror, bswap
/// The `imm` field is the immediate operand (right-hand side).
///
/// Example: ((raw - 0xF) ^ 0xE0) >> 0xF + 1
///   steps = [{sub, 0xF}, {xor, 0xE0}, {lsr, 0xF}, {add, 1}]
struct OpcodeDeobfStep {
    enum class Op : uint8_t {
        sub, add, xor_, and_, or_, lsr, lsl, mul,
        ror,    // rotate-right by imm bits
        bswap,  // byte-swap (imm = byte width: 2/4/8)
        neg,    // two's complement negate (imm ignored)
        not_,   // bitwise NOT (imm ignored)
    } op;
    uint64_t imm = 0;
};

/// Hint about opcode encoding format.
///
/// Three decode modes (mutually exclusive; priority: Mode B > Mode A):
///
/// Mode A – Memory read + deobfuscation pipeline (classic):
///   1. Read `opcode_size` bytes from (vm_pc_value + opcode_byte_offset).
///   2. Apply `opcode_mask` and `opcode_shift` to extract the raw opcode field.
///   3. Apply each step in `deobfuscation_steps` in order.
///
/// Mode B – Register snapshot (post-decode):
///   When `opcode_from_reg != 0xFF`, skip the memory read entirely and
///   read the already-decoded opcode directly from that register at the
///   moment of dispatch (e.g. x0 after the decoder stub has run).
///   All Mode A fields are ignored in this mode.
struct OpcodeFormatHint {
    // ── Mode A: memory read ──────────────────────────────────────────────
    uint8_t  opcode_size = 0;           // Bytes per opcode (1/2/4/8); 0 = unknown
    uint8_t  opcode_byte_offset = 0;    // Byte offset of opcode field within instruction
                                        // E.g. if insn is [imm16][opcode8], set offset=2, size=1
    uint64_t opcode_mask = UINT64_MAX;  // Mask applied after load (default: no masking)
    uint8_t  opcode_shift = 0;          // Right shift after masking
    /// Ordered deobfuscation transforms applied to the (masked+shifted) value.
    std::vector<OpcodeDeobfStep> deobfuscation_steps;

    // ── Mode B: register snapshot ────────────────────────────────────────
    /// Host register index that holds the decoded opcode at dispatch time.
    /// 0xFF = mode B disabled (use mode A).
    uint8_t  opcode_from_reg = 0xFF;
};

/// Hint about a VM context structure.
struct VMContextHint {
    uint8_t ctx_base_reg = 0xFF;       // Register holding vm_ctx pointer
    /// Named fields at known offsets within the vm_ctx struct.
    struct Field {
        uint32_t    offset;            // byte offset from ctx_base
        uint8_t     size = 8;          // field width in bytes (1/2/4/8); default 8
        std::string name;              // display name (e.g. "ip", "sp", "flags")
        bool        is_pointer = false;// display as pointer (0x...) vs integer
    };
    std::vector<Field> fields;
};

/// Layout of the VM's virtual register file (for register-machine VMs).
/// Describes named VM registers stored at fixed offsets within the vm_ctx
/// struct (or at a separate rf_base_reg-relative region).
///
/// Register machine and stack machine are NO LONGER mutually exclusive:
/// a VM can have both named VM registers (regs) AND an operand stack
/// (stack_sp_offset).  When both are provided, both panels are shown.
struct VMRegisterFileHint {
    // ── Register machine ────────────────────────────────────────────────
    /// Host register holding the VM register-file base pointer.
    /// 0xFF = use ctx_base_reg from VMContextHint (fallback).
    uint8_t rf_base_reg = 0xFF;

    /// Named VM registers.  offset is relative to rf_base_reg.
    struct VMReg {
        uint32_t    offset;     // byte offset from RF base
        uint8_t     size = 8;   // register width in bytes (1/2/4/8/16)
        std::string name;       // e.g. "R0", "V0", "PC", "FLAGS"
        bool        is_float = false;  // display as float (only for size==4/8)
        bool        is_pointer = false;// display as pointer (0x...)
    };
    std::vector<VMReg> regs;

    // ── Stack machine ────────────────────────────────────────────────────
    /// Byte offset from rf_base (or ctx_base) where the VM stack pointer
    /// value lives.  0xFFFFFFFF = no stack panel.
    uint32_t stack_sp_offset = 0xFFFFFFFFu;
    /// Number of stack slots visible in the VM stack panel (0 = auto/8).
    uint32_t stack_depth = 0;
    /// Byte size of each stack element (1/2/4/8).
    uint8_t  stack_elem_size = 8;

    /// Stack growth direction.
    /// Descending (default, most common): SP points to last pushed item.
    ///   TOS = *SP, next = *(SP + elem), ...
    /// Ascending: SP points to next free slot.
    ///   TOS = *(SP - elem), next = *(SP - 2*elem), ...
    enum class StackDirection : uint8_t {
        Descending = 0,  // SP = top-of-stack (full-descending)
        Ascending  = 1,  // SP = next-free-slot (full-ascending / empty-ascending)
    };
    StackDirection stack_direction = StackDirection::Descending;

    // ── Helpers ──────────────────────────────────────────────────────────
    bool has_regs()  const { return !regs.empty(); }
    bool has_stack() const { return stack_sp_offset != 0xFFFFFFFFu; }
    bool is_mixed()  const { return has_regs() && has_stack(); }
};

/// Disassembly annotation for one VM handler: maps native PC → asm text.
/// Provided by the user from static analysis (IDA / objdump output).
/// The VM instruction panel uses this to annotate each VMStep with the
/// human-readable asm of the handler body.
struct HandlerAsmEntry {
    uint64_t    pc;       // static PC (without slide)
    std::string text;     // e.g. "ADD  x0, x1, x2"
};

/// Full asm map: one entry per handler, list of (pc, asm) pairs.
struct HandlerAsmHint {
    /// handler_entry_pc (static) → ordered list of asm lines in that handler.
    std::map<uint64_t, std::vector<HandlerAsmEntry>> handler_asm;
};

// ─── VMConfig ────────────────────────────────────────────────────────────────

/// Configuration for VMAbstractPass.  All hints are optional.
///
/// ⚠️ Auto-detection caveat: the heuristic dispatcher auto-detection
/// (`auto_detect == true` with no `dispatcher` hint) works purely off loop
/// iteration counts + indirect-branch shape.  In practice it has a very high
/// false-positive/false-negative rate on real (non-synthetic) traces — it
/// frequently locks onto the wrong loop or misses ThreadedCode/CallTable VMs
/// entirely.  Product surfaces (CLI / GUI / MCP) therefore default this to
/// `false` and require the caller to supply at least a `dispatcher` hint
/// (or another static hint) obtained from static analysis (IDA/Ghidra) before
/// running the pass.  This field only controls the pass's own internal
/// fallback behavior — it defaults to `true` here so the pass remains usable
/// as a general-purpose library/unit-testable component; callers that expose
/// this to end users should keep it hint-gated.
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

    // ── Dispatch topology hints ──────────────────────────────────────────
    /// Force a specific dispatch type instead of auto-detecting.
    /// Useful when the trace contains a ThreadedCode VM that has no central
    /// dispatch loop (each handler tail-chains to the next via BR Xn).
    /// DispatchType::Unknown = auto-detect (default).
    DispatchType dispatch_type_hint = DispatchType::Unknown;

    /// ThreadedCode: set of "fetch+dispatch" PCs that appear in every handler's
    /// tail before the BR Xn that chains to the next handler.
    /// These are the tail-call trampolines or inline fetch sequences.
    /// When provided together with dispatch_type_hint == ThreadedCode,
    /// the pass uses a ThreadedCollector instead of VMCollector.
    std::vector<uint64_t> threaded_dispatch_pcs;

    // ── Static hints ─────────────────────────────────────────────────────
    std::optional<DispatcherHint>  dispatcher;
    std::vector<uint64_t>          handler_entry_pcs;    // Known handler entry PCs
    std::optional<VMPCHint>        vm_pc;
    std::optional<OpcodeFormatHint> opcode_format;
    std::optional<VMContextHint>   vm_context;

    /// Human-provided handler semantic labels: handler_entry_pc → name.
    /// E.g. {0x5000: "ADD", 0x5100: "LOAD", 0x5200: "BRANCH"}.
    std::map<uint64_t, std::string> handler_names;

    /// VM register file layout (for the VM Workspace register panel).
    /// Optional — when absent the panel falls back to showing vm_context fields.
    std::optional<VMRegisterFileHint> vm_register_file;

    /// Static asm annotations for each handler body (for the VM instruction panel).
    /// Optional — when absent the panel shows native PC ranges only.
    std::optional<HandlerAsmHint> handler_asm;

    /// True if the caller has provided at least one piece of static analysis
    /// hint (dispatcher, handler entries, VM-PC, opcode format, context,
    /// register file, or forced dispatch type).  Product surfaces use this
    /// to decide whether it is safe to run the pass at all — see the
    /// auto-detection caveat above.
    bool has_any_static_hint() const {
        return dispatcher.has_value()
            || !handler_entry_pcs.empty()
            || vm_pc.has_value()
            || opcode_format.has_value()
            || vm_context.has_value()
            || vm_register_file.has_value()
            || handler_asm.has_value()
            || !handler_names.empty()
            || dispatch_type_hint != DispatchType::Unknown
            || !threaded_dispatch_pcs.empty();
    }
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

    /// VM register file snapshot at this step (from VMRegisterFileHint).
    /// Pairs of (reg_name, raw_u64_value) read from the RF base.
    /// For stack machines: pairs of ("SP", sp_value) + ("S0"…"Sn", slot_value).
    std::vector<std::pair<std::string, uint64_t>> vm_regs;
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

    // ── Hints carried into result (for VM Workspace UI) ──────────────────
    /// VM register file layout hint — copied from VMConfig.
    std::optional<VMRegisterFileHint> vm_register_file;
    /// Handler asm map — copied from VMConfig (static PC → asm lines).
    std::optional<HandlerAsmHint>     handler_asm;

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

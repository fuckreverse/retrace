#pragma once

// ═══════════════════════════════════════════════════════════════════════════════
// VM Abstract Pass — Virtual Machine execution abstraction driven entirely by
// static-analysis hints.
//
// This pass does NOT attempt to discover VM structure (dispatcher location,
// VM-PC register, architecture type, dispatch topology, opcode encoding) from
// the trace itself. Static analysis (IDA/Ghidra) can determine these facts
// deterministically and cheaply; trying to re-derive them from a handful of
// dynamic samples is strictly worse — lower confidence, higher cost, and
// wrong on anything CFF-obfuscated. All structural facts are therefore
// required inputs (VMConfig hints), sourced from static analysis.
//
// What this pass DOES do dynamically, given those hints: it walks the trace
// once to attribute native instructions to VM dispatch cycles / handler
// executions, and produces the execution-time data that only a trace can
// provide — handler execution counts, register/memory read-write masks,
// observed opcode values, and per-step VM register/context/stack snapshots.
// This is the data static analysis cannot give you, and it is also the
// natural way to cross-check a static hint (e.g. "this handler's assumed
// register effects don't match what actually happened").
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

/// VM architecture classification. This is a static fact about the VM's
/// design (does it use an operand stack or a register file?) and is ALWAYS
/// supplied via `VMConfig::arch_type_hint` — the pass never guesses it from
/// memory-access statistics (a few dozen samples cannot reliably distinguish
/// "stack machine with a wide instruction format" from "register machine
/// with unbalanced handlers", and static analysis already knows the answer
/// for free). Prefer reading `VMConfig::vm_register_file` directly
/// (`has_stack()` / `has_regs()` / `is_mixed()`) when you need this
/// information programmatically — `arch_type_hint` exists mainly as a
/// human-readable label for display.
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

/// One step in an opcode deobfuscation pipeline.
/// Applied in order after loading the raw bytes from memory.
///
/// Supported ops:  sub, add, xor, and, or, lsr, lsl, mul, ror, bswap, neg, not
/// The `imm` field is the immediate operand (right-hand side).
///
/// Stateful rolling-key ops (xor_rolling, add_rolling, sub_rolling):
///   These maintain a rolling key that is updated after each VM step.
///   `imm` is the INITIAL key value for the first opcode; after each
///   decoded opcode, the key is updated by a configurable rule (see
///   OpcodeFormatHint::rolling_key_update).
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

        // ── Rolling-key stateful ops ─────────────────────────────────
        // The `imm` field serves as the INITIAL key; it evolves across
        // VM steps according to `rolling_key_update` (see OpcodeFormatHint).
        xor_rolling,  // val ^= rolling_key (key evolves per step)
        add_rolling,  // val += rolling_key
        sub_rolling,  // val -= rolling_key
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
/// Rule for updating the rolling key after each decoded opcode.
/// Applied after the decode pipeline produces a final opcode value.
enum class RollingKeyUpdate : uint8_t {
    XorOpcode,  // key ^= decoded_opcode  (default)
    AddOpcode,  // key += decoded_opcode
    SubOpcode,  // key -= decoded_opcode
    HashOpcode, // key = (key * 31) + decoded_opcode  (simple hash)
};

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

    // ── Rolling key ──────────────────────────────────────────────────────
    /// How to update rolling-key state after each decoded opcode.
    /// Only relevant when deobfuscation_steps contains a rolling-key op
    /// (xor_rolling / add_rolling / sub_rolling).  Ignored otherwise.
    RollingKeyUpdate rolling_key_update = RollingKeyUpdate::XorOpcode;
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
///
/// Two storage modes per register:
///   (a) Memory-backed (default): rf_base + offset → MemoryModel read.
///   (b) Host-register-backed:    from_host_reg != 0xFF → RegisterFile read.
///       For lightweight VMs that keep VM state in callee-saved AArch64
///       registers (e.g. x19-x28) instead of a heap-allocated struct.
///       When from_host_reg is set, offset/size/is_float are ignored.
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

        /// Host register index (0-28) that holds this VM register.
        /// 0xFF (default) = memory-backed (use rf_base + offset).
        /// When set, the VM register value is read directly from the
        /// AArch64 host register file (RegisterFile::state_before) at
        /// dispatch time, bypassing MemoryModel entirely.
        uint8_t     from_host_reg = 0xFF;
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

/// Configuration for VMAbstractPass.  This pass is entirely hint-driven: it
/// requires at least a `dispatcher` (or `threaded_dispatch_pcs`) hint telling
/// it WHERE the VM dispatch happens in the trace — it never scans loops
/// looking for "VM-shaped" candidates. Product surfaces (CLI / GUI / MCP)
/// enforce this via `has_any_static_hint()` before registering the pass.
///
/// Rationale: dispatcher location, VM-PC register, dispatch topology, and
/// architecture type are all static facts fully determined by the binary —
/// static analysis (IDA/Ghidra) resolves them with 100% confidence in
/// seconds. Re-deriving them from a handful of dynamic samples (loop
/// iteration counts, register step patterns, load/store ratios) is strictly
/// worse on every axis: lower confidence, more expensive, and outright wrong
/// on CFF-obfuscated or ThreadedCode VMs where no single "candidate loop"
/// exists at all. This pass's job is to take those static facts as given and
/// answer the questions only a trace CAN answer: how many times did each
/// handler actually run, what opcode values were actually observed, what did
/// the VM register file / stack actually contain at each step.
struct VMConfig {
    /// Minimum number of distinct handler entry PCs required for the result
    /// to be considered a valid VM (sanity check on the hinted dispatcher,
    /// not a detection threshold — the dispatcher location itself always
    /// comes from a hint, never from scanning).
    uint32_t min_handler_count = 3;

    /// Hint about VM architecture type (stack machine vs register machine).
    /// This is a static fact — always supplied by the caller from static
    /// analysis. Left at Unknown when not provided; the pass never infers it
    /// from memory-access statistics.
    VMArchType arch_type_hint = VMArchType::Unknown;

    // ── Dispatch topology hints ──────────────────────────────────────────
    /// Dispatch topology, from static analysis. DispatchType::Unknown means
    /// the pass falls back to a purely mechanical, non-statistical
    /// classification for loop-based topologies (CallTable if the dispatch
    /// instruction is BLR, IndirectBranch otherwise) — see
    /// `classify_dispatch_type()`. This is NOT a detection heuristic: it
    /// reads a single already-hinted instruction's encoding, it does not
    /// search for or score anything.
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
    std::optional<OpcodeFormatHint> opcode_format;
    std::optional<VMContextHint>   vm_context;

    /// Human-provided handler semantic labels: handler_entry_pc → name.
    /// E.g. {0x5000: "ADD", 0x5100: "LOAD", 0x5200: "BRANCH"}.
    std::map<uint64_t, std::string> handler_names;

    /// VM register file layout (for the VM Workspace register panel).
    /// Optional — when absent the panel falls back to showing vm_context fields.
    std::optional<VMRegisterFileHint> vm_register_file;

    /// Base address for computing inst_file_offset per step.
    /// When set, the pass computes `inst_file_offset = vm_pc - inst_file_offset_base`
    /// for every VM step.  This is the offset of the current instruction within
    /// the bytecode buffer — useful for disassemblers and cross-referencing
    /// with static bytecode dumps.
    /// If 0 (default), the pass tries to read a ctx_field named "bytecode_base"
    /// and use its value as the base.
    uint64_t inst_file_offset_base = 0;
    bool     inst_file_offset_base_set = false;  // true when explicitly configured

    /// Static asm annotations for each handler body (for the VM instruction panel).
    /// Optional — when absent the panel shows native PC ranges only.
    std::optional<HandlerAsmHint> handler_asm;

    // ── Operand decoding ─────────────────────────────────────────────
    /// Description of operand fields within each VM instruction word.
    /// Enables per-step operand decoding (VMStep::operands).
    /// Optional — when absent only the opcode is decoded.
    struct OperandFieldDesc {
        std::string name;           // e.g. "dst", "src1", "imm"
        uint8_t     byte_offset;    // byte offset within the instruction
        uint8_t     size;           // field width in bytes (1/2/4/8)
        uint64_t    mask = UINT64_MAX; // mask applied after load
        uint8_t     shift = 0;      // right-shift after masking
        /// Per-field deobfuscation (same pipeline as opcode).
        std::vector<OpcodeDeobfStep> deobfuscation_steps;
    };
    struct OperandFormatHint {
        /// Total instruction width in bytes (opcode + operands).
    /// When non-zero AND a VM-PC field is configured, the pass computes
    /// `instruction_size = max(opcode_byte_offset+opcode_size, max(operand ends))`
    /// and can report it per-step (useful for disassemblers).
        uint8_t instruction_size = 0;
        /// Ordered list of operand field descriptors.
        std::vector<OperandFieldDesc> fields;
    };
    std::optional<OperandFormatHint> operand_format;

    /// True if the caller has provided at least one piece of static analysis
    /// hint (dispatcher, handler entries, VM-PC, opcode format, context,
    /// register file, or dispatch type). The pass refuses to run without at
    /// least a `dispatcher` (or `threaded_dispatch_pcs`) hint — product
    /// surfaces use this to fail fast with an actionable error instead of
    /// silently doing nothing useful.
    bool has_any_static_hint() const {
        return dispatcher.has_value()
            || !handler_entry_pcs.empty()
            || opcode_format.has_value()
            || vm_context.has_value()
            || vm_register_file.has_value()
            || handler_asm.has_value()
            || !handler_names.empty()
            || dispatch_type_hint != DispatchType::Unknown
            || !threaded_dispatch_pcs.empty()
            || operand_format.has_value();
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

/// Decoded operand of a single VM instruction.
struct VMOperand {
    std::string name;           // field name (from OperandFieldDesc::name)
    uint64_t    value = 0;      // raw decoded value (after mask+shift+deobf)
    uint8_t     size_bytes = 0; // original byte width of the field
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

    /// Bytecode offset of this instruction (vm_pc - bytecode_base).
    /// Populated when a "bytecode_base" ctx_field or inst_file_offset_base hint is configured.
    uint64_t inst_file_offset = 0;
    bool     inst_file_offset_valid = false;

    /// VM context field snapshots at this step (from VMContextHint).
    /// Pairs of (field_name, value) read from the context struct.
    std::vector<std::pair<std::string, uint64_t>> ctx_fields;

    /// VM register file snapshot at this step (from VMRegisterFileHint).
    /// Pairs of (reg_name, raw_u64_value) read from the RF base.
    /// For stack machines: pairs of ("SP", sp_value) + ("S0"…"Sn", slot_value).
    std::vector<std::pair<std::string, uint64_t>> vm_regs;

    /// Decoded operand fields for this VM instruction (from OperandFormatHint).
    /// Empty when no operand format hint is provided or decode fails.
    std::vector<VMOperand> operands;
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
    // VM-PC is no longer a separate hint — it is derived from a field named
    // "pc" or "ip" in vm_context->ctx_fields or vm_register_file->regs.
    // vm_pc_tracked is true when such a field was found and successfully
    // read at least once.
    bool     vm_pc_tracked = false;    // True if VM-PC field found in ctx/regs
    uint64_t bytecode_base = 0;        // Inferred bytecode base address (min VM-PC)
    uint64_t bytecode_end = 0;         // Inferred bytecode end address (max VM-PC + opcode_size)

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

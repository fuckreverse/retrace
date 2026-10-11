#pragma once

// ─── Shared infrastructure for TaintPass (forward) and BackwardTaintPass ──
//
// Both passes walk the trace instruction-by-instruction and need the same
// three primitives:
//   1. AArch64 ABI constants (argument/return/link registers).
//   2. A rule for which registers to exclude from data-flow tracking
//      (NZCV/SP/PC, unless explicitly opted in).
//   3. Overlap-aware memory range matching, so that partial/unaligned
//      accesses to a tainted memory region are still recognized (this is
//      what previously made BackwardTaintPass's memory handling strictly
//      more precise than TaintPass's exact-address-only lookup).
//
// Centralizing these here means a future fix (e.g. a new excluded register,
// or a memory-overlap edge case) only needs to happen once instead of being
// duplicated — and silently drifting — across both passes.

#include "common/types.h"
#include "io/trace_reader.h"
#include "core/instruction_decoder.h"

#include <cstdint>

namespace tenet {

// ─── AArch64 ABI constants ─────────────────────────────────────────────────

inline constexpr uint8_t kTaintAbiArgFirst = 0;   // X0
inline constexpr uint8_t kTaintAbiArgLast  = 7;   // X7
inline constexpr uint8_t kTaintAbiRetReg   = 0;   // X0 (return value)
inline constexpr uint8_t kTaintRegLR       = 30;  // X30 / LR

/// Check if a register is an ABI argument register (X0-X7).
inline bool is_abi_arg_reg(uint8_t reg) {
    return reg >= kTaintAbiArgFirst && reg <= kTaintAbiArgLast;
}

// ─── Register exclusion rule ────────────────────────────────────────────────

/// Whether `reg_idx` should be excluded from taint/data-flow tracking.
/// NZCV is always excluded (it's a flags register, not a data value).
/// SP/PC are excluded unless the caller explicitly opts in (most analyses
/// care about general-purpose data flow, not stack-pointer/control-flow
/// bookkeeping).
struct TaintRegFilter {
    bool include_sp = false;
    bool include_pc = false;

    bool should_exclude(uint8_t reg_idx) const {
        if (reg_idx == IDX_NZCV) return true;
        if (reg_idx == IDX_SP && !include_sp) return true;
        if (reg_idx == IDX_PC && !include_pc) return true;
        return false;
    }
};

// ─── Memory range overlap ──────────────────────────────────────────────────

/// Whether a byte range [a_addr, a_addr+a_size) overlaps [b_addr, b_addr+b_size).
/// This is the precise test: any partial overlap counts, not just exact
/// address equality. Using this (instead of comparing start addresses only)
/// is what allows differently-sized/offset accesses to the same memory
/// region to be correctly linked during taint propagation.
inline bool mem_ranges_overlap(uint64_t a_addr, uint64_t a_size,
                                uint64_t b_addr, uint64_t b_size) {
    uint64_t a_end = a_addr + a_size;
    uint64_t b_end = b_addr + b_size;
    return a_addr < b_end && b_addr < a_end;
}

/// Whether any byte in [addr, addr+size) is present in a tainted-address set.
/// `Set` only needs to support `.contains(uint64_t)` (e.g. roaring::Roaring64Map).
///
/// Taint state is tracked as a set of individually-tainted *byte addresses*
/// (each store adds its start address, see TaintPass::track_memory_sinks),
/// not as explicit [addr,size) ranges. So "does this read overlap a tainted
/// store" reduces to "is the store's start address inside the read range" —
/// checking each byte offset in the (typically <= 16 byte) read is exact and
/// cheap, and is what makes forward-taint's memory handling as precise as
/// BackwardTaintPass's explicit range-overlap check.
template <typename Set>
inline bool mem_range_hits_tainted_set(const Set& tainted, uint64_t addr, uint64_t size) {
    if (size == 0) return tainted.contains(addr);
    for (uint64_t off = 0; off < size; off++) {
        if (tainted.contains(addr + off)) return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// Instruction classification (shared Triton / heuristic strategy)
// ═══════════════════════════════════════════════════════════════════════════
//
// Both the forward and backward taint engines need to answer the same
// question for each instruction: "which registers does it write, which does
// it read, does it touch memory, is it a call site?" The only difference
// between the Triton-backed and heuristic-backed answer is *how* that
// question is answered (precise semantics vs. reg_diff inference).
//
// TaintInstructionInfo + the two classify_* functions below capture that
// shared shape so both passes can drive the same main loop with a strategy
// (classifier) injected — instead of re-implementing the loop twice.

inline constexpr uint8_t kTaintMaxInfoRegs = 16;

/// Describes the register/memory classification of one instruction, as seen
/// by either the Triton-precise or heuristic classifier.
struct TaintInstructionInfo {
    /// All registers WRITTEN by this instruction (potential definitions).
    uint8_t written_regs[kTaintMaxInfoRegs];
    uint8_t n_written = 0;

    /// All registers READ by this instruction (potential sources/sinks).
    uint8_t read_regs[kTaintMaxInfoRegs];
    uint8_t n_read = 0;

    /// Whether this instruction writes LR (i.e., is a BL call site).
    bool is_bl_site = false;

    /// Whether this instruction has semantic memory reads.
    bool has_memory_reads = false;

    /// False if the instruction could not be classified (e.g., no opcode
    /// bytes available for Triton lookup). Callers should skip such insts.
    bool valid = true;

    /// Capstone recovered actual source operands rather than reg_diff guesses.
    bool has_decoded_operands = false;

    void add_written(uint8_t reg_id) {
        if (n_written < kTaintMaxInfoRegs) written_regs[n_written++] = reg_id;
    }
    void add_read(uint8_t reg_id) {
        if (n_read < kTaintMaxInfoRegs) read_regs[n_read++] = reg_id;
    }

    bool writes_reg(uint8_t reg_id) const {
        for (uint8_t i = 0; i < n_written; i++)
            if (written_regs[i] == reg_id) return true;
        return false;
    }
};

/// Heuristic classifier: uses reg_diff entries to infer written registers.
/// Capstone supplies read operands when code is available; otherwise reg_diff
/// entries are conservatively treated as potential sources as well as writes.
inline TaintInstructionInfo classify_inst_heuristic(const InstView& inst,
                                                   InstructionDecoder& decoder,
                                                   const CodeTable& code_table) {
    TaintInstructionInfo info;

    for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
        auto diff = inst.reg_diff(i);
        info.add_written(diff.index);
        if (diff.index == kTaintRegLR) {
            info.is_bl_site = true;
        }
    }

    // reg_diff records writes, not input operands. Decode the opcode so an
    // unchanged source register still propagates taint, while a constant
    // overwrite terminates it. Retain conservative inference for missing code.
    auto decoded = decoder.decode(inst.pc, code_table);
    if (decoded && decoded->mnemonic_sv() != ".word") {
        info.has_decoded_operands = true;
        for (uint8_t i = 0; i < decoded->regs_read_count; i++) {
            info.add_read(decoded->regs_read[i]);
        }
    } else {
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            info.add_read(inst.reg_diff(i).index);
        }
    }

    // Heuristic mode has no semantic memory-access info; always consider
    // memory reads possible and let the caller inspect inst.mem_access().
    info.has_memory_reads = true;

    return info;
}

}  // namespace tenet

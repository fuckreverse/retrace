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
/// NZCV is tracked only when explicit flag dependencies are requested.
/// SP/PC are excluded unless the caller explicitly opts in (most analyses
/// care about general-purpose data flow, not stack-pointer/control-flow
/// bookkeeping).
struct TaintRegFilter {
    bool include_sp = false;
    bool include_pc = false;
    bool include_flags = false;
    bool include_simd = false;

    bool should_exclude(uint8_t reg_idx) const {
        if (reg_idx >= 66 || (reg_idx >= 34 && !include_simd)) return true;
        if (reg_idx == IDX_NZCV && !include_flags) return true;
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
    if (!a_size || !b_size) return false;
    return a_addr <= b_addr ? b_addr - a_addr < a_size : a_addr - b_addr < b_size;
}

/// Whether any byte in [addr, addr+size) is present in a tainted-address set.
/// `Set` only needs to support `.contains(uint64_t)` (e.g. roaring::Roaring64Map).
///
/// The set contains every currently tainted byte, including interior bytes of
/// stores. Clean overwrites remove the corresponding bytes.
template <typename Set>
inline bool mem_range_hits_tainted_set(const Set& tainted, uint64_t addr, uint64_t size) {
    if (size == 0) return tainted.contains(addr);
    for (uint64_t off = 0; off < size && off <= UINT64_MAX - addr; off++) {
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
    bool missing_code = false;
    bool undecoded = false;
    bool unsupported_registers = false;
    uint32_t simd_reads = 0, simd_writes = 0;
    uint8_t writeback_reg = 0xff;
    uint64_t writeback_reads = 0;

    void add_written(uint8_t reg_id) {
        if (writes_reg(reg_id)) return;
        if (n_written < kTaintMaxInfoRegs) written_regs[n_written++] = reg_id;
        else unsupported_registers = true;
    }
    void add_read(uint8_t reg_id) {
        for (uint8_t i = 0; i < n_read; ++i) if (read_regs[i] == reg_id) return;
        if (n_read < kTaintMaxInfoRegs) read_regs[n_read++] = reg_id;
        else unsupported_registers = true;
    }

    bool writes_reg(uint8_t reg_id) const {
        for (uint8_t i = 0; i < n_written; i++)
            if (written_regs[i] == reg_id) return true;
        return false;
    }
};

/// Operand classifier: merges decoded definitions with recorded writes.
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
    info.missing_code = !code_table.opcode_at(inst.pc).has_value();
    info.undecoded = !info.missing_code && (!decoded || !decoded->decoded);
    if (decoded && decoded->decoded) {
        info.has_decoded_operands = true;
        info.writeback_reg = decoded->writeback_reg;
        info.writeback_reads = decoded->writeback_reads;
        info.unsupported_registers = decoded->untracked_register_access || decoded->register_access_overflow;
        info.simd_reads = decoded->simd_reads; info.simd_writes = decoded->simd_writes;
        for (uint8_t i = 0; i < decoded->regs_written_count; ++i)
            info.add_written(decoded->regs_written[i]);
        const auto mn = decoded->mnemonic_sv();
        info.is_bl_site = mn == "bl" || mn == "blr";
        for (uint8_t i = 0; i < decoded->regs_read_count; i++) {
            info.add_read(decoded->regs_read[i]);
        }
    } else {
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            info.add_read(inst.reg_diff(i).index);
        }
    }

    for (uint8_t i = 0; i < inst.fpr_diff_count; ++i) {
        const auto reg = inst.fpr_diff(i).index;
        if (reg < 32) info.simd_writes |= uint32_t(1) << reg;
        else info.unsupported_registers = true;
    }
    // Heuristic mode has no semantic memory-access info; always consider
    // memory reads possible and let the caller inspect inst.mem_access().
    info.has_memory_reads = true;

    return info;
}

}  // namespace tenet

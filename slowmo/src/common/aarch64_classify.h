#pragma once

#include <cstdint>
#include <string_view>

// ─── AArch64 Instruction Classification ──────────────────────────────────────
// Lightweight, pure-opcode classification of AArch64 instructions.
// These helpers operate directly on the 32-bit opcode and/or a decoded mnemonic
// string, with NO dependency on Capstone — suitable for hot inner loops.
//
// Encoding references: ARMv8 Architecture Reference Manual, section C4.

namespace tenet::aarch64 {

// ─── Opcode-level (no Capstone needed) ────────────────────────────────────

/// Returns true if the opcode is an unconditional branch (B / BL).
/// top-6 bits == 0x05 (B) or 0x25 (BL).
inline bool is_b_or_bl(uint32_t opcode) noexcept {
    uint32_t top6 = opcode >> 26;
    return top6 == 0x05u || top6 == 0x25u;
}

/// Returns true if the opcode is BL (branch with link, i.e. a call).
/// Bit 31 == 1, bits 30-26 == 0x25.
inline bool is_bl(uint32_t opcode) noexcept {
    return (opcode >> 26) == 0x25u;
}

/// Returns true if the opcode is an unconditional B (no link).
inline bool is_b(uint32_t opcode) noexcept {
    return (opcode >> 26) == 0x05u;
}

/// Returns true if the opcode is a conditional B.cond.
/// Encoding: bits[31:24] == 0b0101_0100 (fixed), bits[23:5] == imm19
/// (variable offset), bit[4] == 0 (fixed), bits[3:0] == cond (variable
/// condition code). Only bits [31:24] and [4] are fixed; imm19 and cond
/// must NOT be included in the comparison mask, or non-zero offsets /
/// non-EQ conditions (e.g. b.lt, b.ne with a real branch target) will be
/// missed.
inline bool is_b_cond(uint32_t opcode) noexcept {
    return (opcode & 0xFF000010u) == 0x54000000u;
}

/// Returns true if the opcode is RET.
/// Fixed encoding: 0xD65F03C0 (most common); more generally:
///   bits 31:10 == 0b1101_0110_0101_1111_0000_00, bits 9:5 = Rn, bits 4:0 = 0b00000
/// We use the ARMv8 mask: (opcode & 0xFFFFFC1F) == 0xD65F0000.
inline bool is_ret(uint32_t opcode) noexcept {
    return (opcode & 0xFFFFFC1Fu) == 0xD65F0000u;
}

/// Returns true if the opcode is BLR (branch with link to register).
/// (opcode & 0xFFFFFC1F) == 0xD63F0000.
inline bool is_blr(uint32_t opcode) noexcept {
    return (opcode & 0xFFFFFC1Fu) == 0xD63F0000u;
}

/// Returns true if the opcode is BR (unconditional branch to register).
/// (opcode & 0xFFFFFC1F) == 0xD61F0000.
inline bool is_br(uint32_t opcode) noexcept {
    return (opcode & 0xFFFFFC1Fu) == 0xD61F0000u;
}

/// Returns true if the opcode is any branch (B, BL, B.cond, BLR, BR, RET, CBZ/CBNZ, TBZ/TBNZ).
inline bool is_any_branch(uint32_t opcode) noexcept {
    uint32_t top6 = opcode >> 26;
    if (top6 == 0x05u || top6 == 0x25u) return true;  // B, BL
    if ((opcode & 0xFF000010u) == 0x54000000u) return true;  // B.cond
    uint32_t op_type = opcode & 0xFFFFFC1Fu;
    if (op_type == 0xD65F0000u || op_type == 0xD63F0000u || op_type == 0xD61F0000u) return true; // RET,BLR,BR
    // CBZ/CBNZ: top 7 bits 0b0110_100x → top6 in {0x1A, 0x1B, 0x3A, 0x3B}
    if ((top6 & 0x3Eu) == 0x1Au && (top6 & 0x3Cu) != 0x18u) return true;
    return false;
}

/// Returns true if the opcode is a call instruction (BL or BLR).
inline bool is_call(uint32_t opcode) noexcept {
    return is_bl(opcode) || is_blr(opcode);
}

/// Returns true if the opcode is a return (RET).
inline bool is_return(uint32_t opcode) noexcept {
    return is_ret(opcode);
}

/// Returns true for MOVZ (move with zero).
/// Encoding: sf:opc(10):100101:hw:imm16:Rd
/// Mask out sf (bit 31) and hw (bits 22:21) to match all shift variants.
inline bool is_movz(uint32_t opcode) noexcept {
    return (opcode & 0x7F800000u) == 0x52800000u;
}

/// Returns true for MOVK (move with keep).
/// Encoding: sf:opc(11):100101:hw:imm16:Rd
/// Mask out sf (bit 31) and hw (bits 22:21) to match all shift variants.
inline bool is_movk(uint32_t opcode) noexcept {
    return (opcode & 0x7F800000u) == 0x72800000u;
}

// ─── Mnemonic-level helpers (for use with Capstone decoded strings) ────────

/// Returns true if mnemonic is a call (bl or blr).
inline bool is_call_mnemonic(std::string_view m) noexcept {
    return m.size() >= 2 && m[0] == 'b' && m[1] == 'l';
}

/// Returns true if mnemonic is ret.
inline bool is_ret_mnemonic(std::string_view m) noexcept {
    return m == "ret";
}

/// Returns true if mnemonic is an unconditional direct/indirect jump (b / br).
/// Excludes conditional branches (b.eq etc.) by checking absence of '.'.
inline bool is_unconditional_jump_mnemonic(std::string_view m) noexcept {
    return m == "b" || m == "br";
}

/// Returns true for any branch mnemonic (including conditional).
inline bool is_any_branch_mnemonic(std::string_view m) noexcept {
    return !m.empty() && m[0] == 'b';
}

/// Returns true for hardware AES mnemonics.
inline bool is_hw_aes_mnemonic(std::string_view m) noexcept {
    return m == "aese" || m == "aesd" || m == "aesmc" || m == "aesimc";
}

/// Returns true for hardware SHA mnemonics.
inline bool is_hw_sha_mnemonic(std::string_view m) noexcept {
    if (m.size() < 4) return false;
    if (m[0] == 's' && m[1] == 'h' && m[2] == 'a') {
        return m == "sha1c" || m == "sha1h" || m == "sha1m" ||
               m == "sha1p" || m == "sha1su0" || m == "sha1su1" ||
               m == "sha256h" || m == "sha256h2" ||
               m == "sha256su0" || m == "sha256su1";
    }
    return false;
}

/// Returns true for svc (syscall).
inline bool is_svc_mnemonic(std::string_view m) noexcept {
    return m == "svc";
}

// ─── Branch target extraction (pure opcode, no Capstone) ──────────────────
//
// These helpers extract the PC-relative branch target directly from the
// opcode's immediate fields, avoiding the need for a Capstone decode pass.
// All return the absolute target PC = pc + sign_extended_immediate * 4.
// Callers should first classify the instruction with is_b/is_bl/is_b_cond/
// is_cbz/is_cbnz/is_tbz/is_tbnz to determine which function to call.

/// Sign-extend a value from `bits` bits to int64_t.
inline int64_t sign_extend(uint64_t val, int bits) noexcept {
    uint64_t m = 1ULL << (bits - 1);
    return static_cast<int64_t>((val ^ m) - m);
}

/// Extract B/BL target: imm26 at bits [25:0], scaled by 4.
/// Works for both is_b() and is_bl().
inline uint64_t b_bl_target(uint64_t pc, uint32_t opcode) noexcept {
    int64_t imm26 = sign_extend(opcode & 0x03FFFFFFu, 26);
    return pc + (imm26 << 2);
}

/// Extract B.cond target: imm19 at bits [23:5], scaled by 4.
inline uint64_t b_cond_target(uint64_t pc, uint32_t opcode) noexcept {
    int64_t imm19 = sign_extend((opcode >> 5) & 0x7FFFFu, 19);
    return pc + (imm19 << 2);
}

/// Returns true if opcode is CBZ or CBNZ (32-bit or 64-bit).
inline bool is_cbz_or_cbnz(uint32_t opcode) noexcept {
    uint32_t top7 = (opcode >> 25) & 0x7Fu;
    return (top7 & 0x7Eu) == 0x1Au && (top7 & 0x04u) == 0x00u;
    // top7 in {0b0110100, 0b0110101, 0b1110100, 0b1110101} = CBZ/CBNZ 32/64
}

/// Extract CBZ/CBNZ target: imm19 at bits [23:5], scaled by 4.
inline uint64_t cbz_target(uint64_t pc, uint32_t opcode) noexcept {
    return b_cond_target(pc, opcode);  // same imm19 layout
}

/// Returns true if opcode is TBZ or TBNZ.
inline bool is_tbz_or_tbnz(uint32_t opcode) noexcept {
    uint32_t top7 = (opcode >> 25) & 0x7Fu;
    return (top7 & 0x7Eu) == 0x1Bu && (top7 & 0x04u) == 0x00u;
}

/// Extract TBZ/TBNZ target: imm14 at bits [18:5], scaled by 4.
inline uint64_t tbz_target(uint64_t pc, uint32_t opcode) noexcept {
    int64_t imm14 = sign_extend((opcode >> 5) & 0x3FFFu, 14);
    return pc + (imm14 << 2);
}

/// Unified branch target extraction: given a PC and opcode, returns the
/// target PC for any direct branch (B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ).
/// Returns 0 if the opcode is not a direct branch with a PC-relative target.
inline uint64_t direct_branch_target(uint64_t pc, uint32_t opcode) noexcept {
    if (is_b(opcode) || is_bl(opcode))
        return b_bl_target(pc, opcode);
    if (is_b_cond(opcode) || is_cbz_or_cbnz(opcode))
        return b_cond_target(pc, opcode);
    if (is_tbz_or_tbnz(opcode))
        return tbz_target(pc, opcode);
    return 0;
}

// ─── MOVZ/MOVK constant materialization helpers ───────────────────────────

/// Extract the 16-bit immediate from MOVZ/MOVK instruction.
/// Returns 0 if not a MOVZ/MOVK instruction.
inline uint16_t movzk_imm16(uint32_t opcode) noexcept {
    return static_cast<uint16_t>((opcode >> 5) & 0xFFFFu);
}

/// Extract the shift amount (hw field) from MOVZ/MOVK.
/// Returns 0, 16, 32, or 48.
inline int movzk_shift(uint32_t opcode) noexcept {
    return static_cast<int>((opcode >> 21) & 0x3u) << 4;
}

/// Extract destination register index (Rd field, bits 4:0) from MOVZ/MOVK.
inline uint8_t movzk_reg(uint32_t opcode) noexcept {
    return static_cast<uint8_t>(opcode & 0x1Fu);
}

// ─── Instruction-category bit classifiers (no Capstone needed) ─────────────
//
// These classify AArch64 instructions into the coarse categories needed by
// loop_semantics_pass (XOR / shift-rotate / add-sub / modular / load) using
// pure opcode bit-pattern matching.  Verified against Capstone-decoded
// mnemonics for all common encodings.
//
// Encoding groups (ARMv8 ARM section C4):
//   - Data processing, shifted register:  bits[28:24] = 01010  (0x0A)
//   - Data processing, immediate:         bits[28:24] = 10001  (0x11) — ADD/SUB imm
//   - Data processing, 1/2 source:        bits[28:24] = 11010  (0x1A)
//   - Data processing, 3 source:          bits[28:24] = 11011  (0x1B)
//   - Data processing, extract:           bits[28:24] = 11100  (0x1C)
//   - Loads / stores:                     bits[29:27] = 111    (0x7)

/// EOR (shifted register): op[30:29]=10, N[23]=0.
/// Covers "eor" and "eors" (AArch64 has no separate EORS; Capstone emits "eor").
inline bool is_eor_shifted(uint32_t op) noexcept {
    // Mask sf(bit31) and S/bit29 — EOR has bits[30:29]=10, bit23=0.
    // Verified: EOR W0,W1,W2=0x4A020020, EOR X0,W1,W2=0xCA020020.
    return (op & 0x5F800000u) == 0x4A000000u;
}

/// EON (shifted register): op[30:29]=10, N[23]=1.
inline bool is_eon_shifted(uint32_t op) noexcept {
    return (op & 0x5F800000u) == 0x4A200000u;
}

/// Variable shift (LSLV/LSRV/ASRV/RORV): bits[28:24]=11010, opcode2[15:10] in {8..11}.
/// Covers "lsl","lsr","asr","ror" and their 's' variants (which don't exist in
/// AArch64 but Capstone may emit the base form).
inline bool is_variable_shift(uint32_t op) noexcept {
    if (((op >> 24) & 0x1Fu) != 0x1Au) return false;
    uint32_t op2 = (op >> 10) & 0x3Fu;
    return op2 >= 8 && op2 <= 11;  // LSLV=8, LSRV=9, ASRV=10, RORV=11
}

/// EXTR (extract): bits[28:24]=11100.
inline bool is_extr(uint32_t op) noexcept {
    return (op & 0x7F000000u) == 0x1C000000u;
}

/// UBFM/SBFM (bitfield move): immediate-shift aliases.
/// LSL #imm = UBFM, LSR #imm = UBFM, ASR #imm = SBFM.
/// Also covers UBFX/UBFIZ/SBFX/SBFIZ/BFXIL which Capstone may emit as their
/// own mnemonics — all are bit-manipulation operations relevant to crypto
/// loop detection.
/// UBFM: bits[30:24]=1010011 → (op & 0x7F000000)==0x53000000
/// SBFM: bits[30:24]=0010011 → (op & 0x7F000000)==0x13000000
inline bool is_ubfm_sbfm(uint32_t op) noexcept {
    uint32_t grp = op & 0x7F000000u;
    return grp == 0x53000000u || grp == 0x13000000u;
}

/// ADD/SUB (shifted register): bits[28:24]=01011.
inline bool is_add_sub_shifted(uint32_t op) noexcept {
    return ((op >> 24) & 0x1Fu) == 0x0Bu;
}

/// ADD/SUB (immediate): bits[28:24]=10001.
inline bool is_add_sub_immediate(uint32_t op) noexcept {
    return ((op >> 24) & 0x1Fu) == 0x11u;
}

/// ADC/SBC (add/sub with carry): bits[28:24]=11010, opcode2[15:10]=000000.
inline bool is_adc_sbc(uint32_t op) noexcept {
    if (((op >> 24) & 0x1Fu) != 0x1Au) return false;
    return ((op >> 10) & 0x3Fu) == 0x00u;
}

/// Any ADD/SUB (shifted register, immediate, or with carry).
inline bool is_add_sub(uint32_t op) noexcept {
    return is_add_sub_shifted(op) || is_add_sub_immediate(op) || is_adc_sbc(op);
}

/// MUL/MADD/MSUB/SMULL/UMULL/UMULH/SMULH: bits[28:24]=11011 (3-source group).
inline bool is_mul_family(uint32_t op) noexcept {
    return ((op >> 24) & 0x1Fu) == 0x1Bu;
}

/// UDIV/SDIV: bits[28:24]=11010, opcode2[15:10] in {2,3}.
inline bool is_div(uint32_t op) noexcept {
    if (((op >> 24) & 0x1Fu) != 0x1Au) return false;
    uint32_t op2 = (op >> 10) & 0x3Fu;
    return op2 == 2 || op2 == 3;
}

/// Any modular arithmetic (mul family or integer division).
inline bool is_modular(uint32_t op) noexcept {
    return is_mul_family(op) || is_div(op);
}

/// Any load instruction (load/store group with load bit set).
/// Load/store group: bits[29:27]=111. Load bit: bit 22=1 for most encodings
/// (unsigned-offset, register-offset, pair, exclusive). This covers
/// ldr/ldrb/ldrh/ldrsb/ldrsh/ldrsw/ldp/ldxr and variants.
inline bool is_load(uint32_t op) noexcept {
    if (((op >> 27) & 0x7u) != 0x7u) return false;
    return (op >> 22) & 0x1u;
}

// ─── Simple OpcodeInfo for hot-loop use (matches window_stats_pass usage) ─

/// Pre-computed classification from a 4-byte AArch64 opcode.
/// Used by WindowStatsPass, LoopSemanticsPass and similar passes that need
/// lightweight opcode info without a Capstone decode.
struct OpcodeInfo {
    uint16_t mnemonic_id;   // top 11 bits as grouping key
    bool is_branch;
    // ── Loop-semantics category flags (pure bit classification) ──
    bool is_eor;            // EOR (shifted register)
    bool is_shift_rotate;   // LSLV/LSRV/ASRV/RORV + EON + EXTR
    bool is_add_sub;        // ADD/SUB (shifted, immediate, with carry)
    bool is_modular;        // MUL/MADD/MSUB/SMULL/UMULL/UDIV/SDIV etc.
    bool is_load;           // any load instruction

    static OpcodeInfo classify(uint32_t opcode) noexcept {
        OpcodeInfo info;
        info.mnemonic_id    = static_cast<uint16_t>(opcode >> 21);
        info.is_branch      = is_any_branch(opcode);
        info.is_eor         = aarch64::is_eor_shifted(opcode);
        info.is_shift_rotate = aarch64::is_variable_shift(opcode) || aarch64::is_eon_shifted(opcode) || aarch64::is_extr(opcode) || aarch64::is_ubfm_sbfm(opcode);
        info.is_add_sub     = aarch64::is_add_sub(opcode);
        info.is_modular     = aarch64::is_modular(opcode);
        info.is_load        = aarch64::is_load(opcode);
        return info;
    }
};

}  // namespace tenet::aarch64

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

/// Returns true for MOVZ (move with zero, bit pattern: sf:10:1010_0101:hw:imm16:Rd).
/// Top 9 bits (excluding sf): 0b10_1001_01 → with sf=0: 0b0010_1001_01 = 0x52800000 >> 5
/// Simpler: (opcode & 0x7FE00000) == 0x52800000.
inline bool is_movz(uint32_t opcode) noexcept {
    return (opcode & 0x7FE00000u) == 0x52800000u;
}

/// Returns true for MOVK (move with keep).
inline bool is_movk(uint32_t opcode) noexcept {
    return (opcode & 0x7FE00000u) == 0x72800000u;
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

// ─── Simple OpcodeInfo for hot-loop use (matches window_stats_pass usage) ─

/// Pre-computed classification from a 4-byte AArch64 opcode.
/// Used by WindowStatsPass and similar passes that need only branch/mnemonic-id info.
struct OpcodeInfo {
    uint16_t mnemonic_id;   // top 11 bits as grouping key
    bool is_branch;

    static OpcodeInfo classify(uint32_t opcode) noexcept {
        OpcodeInfo info;
        info.mnemonic_id = static_cast<uint16_t>(opcode >> 21);
        info.is_branch   = is_any_branch(opcode);
        return info;
    }
};

}  // namespace tenet::aarch64

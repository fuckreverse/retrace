#include "analysis/passes/constant_materialization_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>
#include <algorithm>
#include <cstring>
#include <array>

namespace tenet {

// ─── AArch64 opcode bit-field extraction ──────────────────────────────────

// MOVZ encoding (AArch64):
//   sf=1 for 64-bit (X), sf=0 for 32-bit (W)
//   opc=10 for MOVZ, opc=11 for MOVK
//   Bit layout: [sf:1][opc:2][100101][hw:2][imm16:16][Rd:5]
//
//   sf  = bit 31
//   opc = bits 30:29
//   fixed = bits 28:23 = 0b100101
//   hw  = bits 22:21
//   imm16 = bits 20:5
//   Rd  = bits 4:0

namespace {

constexpr uint32_t MOVZ_MASK = 0x7F800000u;  // bits 30:23
constexpr uint32_t MOVZ_32   = 0x52800000u;  // sf=0, opc=10, fixed=100101 → W
constexpr uint32_t MOVZ_64   = 0xD2800000u;  // sf=1, opc=10, fixed=100101 → X

constexpr uint32_t MOVK_MASK = 0x7F800000u;
constexpr uint32_t MOVK_32   = 0x72800000u;  // sf=0, opc=11
constexpr uint32_t MOVK_64   = 0xF2800000u;  // sf=1, opc=11

inline uint8_t  extract_rd(uint32_t op)    { return op & 0x1Fu; }
inline uint16_t extract_imm16(uint32_t op) { return (op >> 5) & 0xFFFFu; }
inline uint8_t  extract_hw(uint32_t op)    { return (op >> 21) & 0x3u; }
inline bool     extract_sf(uint32_t op)    { return (op >> 31) & 1u; }

}  // anonymous namespace

// ─── MOVZ / MOVK decoding ─────────────────────────────────────────────────

std::optional<ConstantMaterializationPass::MovImm>
ConstantMaterializationPass::decode_movz(uint32_t opcode) {
    uint32_t masked = opcode & MOVZ_MASK;
    if (masked != MOVZ_32 && masked != MOVZ_64) return std::nullopt;

    MovImm m;
    m.rd      = extract_rd(opcode);
    m.imm16   = extract_imm16(opcode);
    m.hw      = extract_hw(opcode);
    m.is_64bit = extract_sf(opcode);

    // Sanity: 32-bit MOVZ cannot use hw=2 or hw=3
    if (!m.is_64bit && m.hw > 1) return std::nullopt;

    return m;
}

std::optional<ConstantMaterializationPass::MovImm>
ConstantMaterializationPass::decode_movk(uint32_t opcode) {
    uint32_t masked = opcode & MOVK_MASK;
    if (masked != MOVK_32 && masked != MOVK_64) return std::nullopt;

    MovImm m;
    m.rd      = extract_rd(opcode);
    m.imm16   = extract_imm16(opcode);
    m.hw      = extract_hw(opcode);
    m.is_64bit = extract_sf(opcode);

    if (!m.is_64bit && m.hw > 1) return std::nullopt;

    return m;
}

// ─── Constructor ──────────────────────────────────────────────────────────

ConstantMaterializationPass::ConstantMaterializationPass() = default;

// ─── Known constants database ─────────────────────────────────────────────

void ConstantMaterializationPass::build_known_db() {
    if (db_initialized_) return;
    db_initialized_ = true;

    auto add = [this](uint64_t val, const char* name, const char* algo,
                      const char* desc, bool is32 = false) {
        known_db_.emplace(val, KnownConstant(val, name, algo, desc, is32));
        if (is32) {
            auto it = known_db_.find(val);
            known_db_32_.emplace(static_cast<uint32_t>(val & 0xFFFFFFFF), &it->second);
        }
    };

    // ── SHA-256 initial hash values H0-H7 ────────────────────────────────
    add(0x6a09e667, "SHA256_H0", "SHA-256", "Initial hash value H0", true);
    add(0xbb67ae85, "SHA256_H1", "SHA-256", "Initial hash value H1", true);
    add(0x3c6ef372, "SHA256_H2", "SHA-256", "Initial hash value H2", true);
    add(0xa54ff53a, "SHA256_H3", "SHA-256", "Initial hash value H3", true);
    add(0x510e527f, "SHA256_H4", "SHA-256", "Initial hash value H4", true);
    add(0x9b05688c, "SHA256_H5", "SHA-256", "Initial hash value H5", true);
    add(0x1f83d9ab, "SHA256_H6", "SHA-256", "Initial hash value H6", true);
    add(0x5be0cd19, "SHA256_H7", "SHA-256", "Initial hash value H7", true);

    // ── SHA-256 round constants K[0..15] ─────────────────────────────────
    static const uint32_t sha256_k[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    };
    for (int i = 0; i < 16; i++) {
        add(sha256_k[i],
            fmt::format("SHA256_K{}", i).c_str(),
            "SHA-256",
            fmt::format("Round constant K[{}]", i).c_str(),
            true);
    }

    // ── SHA-1 initial hash values ────────────────────────────────────────
    add(0x67452301, "SHA1_H0", "SHA-1", "Initial hash value H0", true);
    add(0xEFCDAB89, "SHA1_H1", "SHA-1", "Initial hash value H1", true);
    add(0x98BADCFE, "SHA1_H2", "SHA-1", "Initial hash value H2", true);
    add(0x10325476, "SHA1_H3", "SHA-1", "Initial hash value H3", true);
    add(0xC3D2E1F0, "SHA1_H4", "SHA-1", "Initial hash value H4", true);

    // ── SHA-1 round constants ────────────────────────────────────────────
    add(0x5A827999, "SHA1_K0", "SHA-1", "Round constant K (0-19)", true);
    add(0x6ED9EBA1, "SHA1_K1", "SHA-1", "Round constant K (20-39)", true);
    add(0x8F1BBCDC, "SHA1_K2", "SHA-1", "Round constant K (40-59)", true);
    add(0xCA62C1D6, "SHA1_K3", "SHA-1", "Round constant K (60-79)", true);

    // ── SHA-512 initial hash values (64-bit) ─────────────────────────────
    add(0x6a09e667f3bcc908ULL, "SHA512_H0", "SHA-512", "Initial hash value H0");
    add(0xbb67ae8584caa73bULL, "SHA512_H1", "SHA-512", "Initial hash value H1");
    add(0x3c6ef372fe94f82bULL, "SHA512_H2", "SHA-512", "Initial hash value H2");
    add(0xa54ff53a5f1d36f1ULL, "SHA512_H3", "SHA-512", "Initial hash value H3");
    add(0x510e527fade682d1ULL, "SHA512_H4", "SHA-512", "Initial hash value H4");
    add(0x9b05688c2b3e6c1fULL, "SHA512_H5", "SHA-512", "Initial hash value H5");
    add(0x1f83d9abfb41bd6bULL, "SHA512_H6", "SHA-512", "Initial hash value H6");
    add(0x5be0cd19137e2179ULL, "SHA512_H7", "SHA-512", "Initial hash value H7");

    // ── MD5 initialization constants ─────────────────────────────────────
    // (same as SHA-1 H0-H3 but in different order — both are registered)
    add(0xd76aa478, "MD5_T1",  "MD5", "Sine table T[1]", true);
    add(0xe8c7b756, "MD5_T2",  "MD5", "Sine table T[2]", true);
    add(0x242070db, "MD5_T3",  "MD5", "Sine table T[3]", true);
    add(0xc1bdceee, "MD5_T4",  "MD5", "Sine table T[4]", true);
    add(0xf57c0faf, "MD5_T5",  "MD5", "Sine table T[5]", true);
    add(0x4787c62a, "MD5_T6",  "MD5", "Sine table T[6]", true);
    add(0xa8304613, "MD5_T7",  "MD5", "Sine table T[7]", true);
    add(0xfd469501, "MD5_T8",  "MD5", "Sine table T[8]", true);

    // ── SM3 initial values IV[0..7] ──────────────────────────────────────
    add(0x7380166f, "SM3_IV0", "SM3", "IV[0]", true);
    add(0x4914b2b9, "SM3_IV1", "SM3", "IV[1]", true);
    add(0x172442d7, "SM3_IV2", "SM3", "IV[2]", true);
    add(0xda8a0600, "SM3_IV3", "SM3", "IV[3]", true);
    add(0xa96f30bc, "SM3_IV4", "SM3", "IV[4]", true);
    add(0x163138aa, "SM3_IV5", "SM3", "IV[5]", true);
    add(0xe38dee4d, "SM3_IV6", "SM3", "IV[6]", true);
    add(0xb0fb0e4e, "SM3_IV7", "SM3", "IV[7]", true);

    // ── SM3 round constants T_j ──────────────────────────────────────────
    add(0x79cc4519, "SM3_TJ_0_15",  "SM3", "T_j for rounds 0-15", true);
    add(0x7a879d8a, "SM3_TJ_16_63", "SM3", "T_j for rounds 16-63", true);

    // ── SM4 system parameter FK[0..3] ────────────────────────────────────
    add(0xa3b1bac6, "SM4_FK0", "SM4", "System parameter FK[0]", true);
    add(0x56aa3350, "SM4_FK1", "SM4", "System parameter FK[1]", true);
    add(0x677d9197, "SM4_FK2", "SM4", "System parameter FK[2]", true);
    add(0xb27022dc, "SM4_FK3", "SM4", "System parameter FK[3]", true);

    // ── SM4 constant key CK[0..3] ────────────────────────────────────────
    add(0x00070e15, "SM4_CK0", "SM4", "Constant key CK[0]", true);
    add(0x1c232a31, "SM4_CK1", "SM4", "Constant key CK[1]", true);
    add(0x383f464d, "SM4_CK2", "SM4", "Constant key CK[2]", true);
    add(0x545b6269, "SM4_CK3", "SM4", "Constant key CK[3]", true);

    // ── AES round constants ──────────────────────────────────────────────
    add(0x01000000, "AES_RCON1", "AES", "Key expansion Rcon[1]", true);
    add(0x02000000, "AES_RCON2", "AES", "Key expansion Rcon[2]", true);
    add(0x04000000, "AES_RCON3", "AES", "Key expansion Rcon[3]", true);
    add(0x08000000, "AES_RCON4", "AES", "Key expansion Rcon[4]", true);
    add(0x10000000, "AES_RCON5", "AES", "Key expansion Rcon[5]", true);
    add(0x20000000, "AES_RCON6", "AES", "Key expansion Rcon[6]", true);
    add(0x40000000, "AES_RCON7", "AES", "Key expansion Rcon[7]", true);
    add(0x80000000, "AES_RCON8", "AES", "Key expansion Rcon[8]", true);
    add(0x1B000000, "AES_RCON9", "AES", "Key expansion Rcon[9]", true);
    add(0x36000000, "AES_RCON10", "AES", "Key expansion Rcon[10]", true);

    // ── ChaCha20 sigma constants ─────────────────────────────────────────
    add(0x61707865, "CHACHA20_SIGMA0", "ChaCha20", "Sigma 'expa'", true);
    add(0x3320646e, "CHACHA20_SIGMA1", "ChaCha20", "Sigma 'nd 3'", true);
    add(0x79622d32, "CHACHA20_SIGMA2", "ChaCha20", "Sigma '2-by'", true);
    add(0x6b206574, "CHACHA20_SIGMA3", "ChaCha20", "Sigma 'te k'", true);

    // ── TEA / XTEA delta ─────────────────────────────────────────────────
    add(0x9E3779B9, "TEA_DELTA", "TEA", "Golden ratio delta constant", true);
    // Full 64-bit golden ratio (used in some custom ciphers)
    add(0x9E3779B97F4A7C15ULL, "PHI_64", "Constant", "64-bit golden ratio (phi)");

    // ── CRC32 polynomial ─────────────────────────────────────────────────
    add(0xEDB88320, "CRC32_POLY", "CRC32", "Reflected polynomial", true);
    add(0x04C11DB7, "CRC32_POLY_NORM", "CRC32", "Normal polynomial", true);

    // ── Blowfish P-array ─────────────────────────────────────────────────
    add(0x243F6A88, "BF_P0", "Blowfish", "P-array P[0] (digits of pi)", true);
    add(0x85A308D3, "BF_P1", "Blowfish", "P-array P[1]", true);
    add(0x13198A2E, "BF_P2", "Blowfish", "P-array P[2]", true);
    add(0x03707344, "BF_P3", "Blowfish", "P-array P[3]", true);

    // ── Curve25519 ───────────────────────────────────────────────────────
    add(0x1DB41, "CURVE25519_A24", "Curve25519", "Constant (A+2)/4 = 121665");

    // ── BLAKE2b IV ───────────────────────────────────────────────────────
    // (Same as SHA-512 H values, already registered above)

    // ── Miscellaneous magic numbers ──────────────────────────────────────
    add(0xDEADBEEF, "DEADBEEF", "Debug", "Debug magic 0xDEADBEEF", true);
    add(0xCAFEBABE, "CAFEBABE", "Java", "Java class file magic", true);
    add(0xFEEDFACE, "FEEDFACE", "MachO", "Mach-O 32-bit magic", true);
    add(0xFEEDFACF, "FEEDFACF", "MachO", "Mach-O 64-bit magic", true);
    add(0xCEFAEDFE, "CEFAEDFE", "MachO", "Mach-O 32-bit reversed", true);
    add(0xCFFAEDFE, "CFFAEDFE", "MachO", "Mach-O 64-bit reversed", true);
}

const KnownConstant* ConstantMaterializationPass::lookup(uint64_t value) const {
    // Try exact 64-bit match first
    auto it = known_db_.find(value);
    if (it != known_db_.end()) return &it->second;

    // Try 32-bit match (value might have upper 32 bits zero)
    if ((value >> 32) == 0) {
        auto it32 = known_db_32_.find(static_cast<uint32_t>(value));
        if (it32 != known_db_32_.end()) return it32->second;
    }

    return nullptr;
}

// ─── Flush a pending constant ─────────────────────────────────────────────

void ConstantMaterializationPass::flush_pending(
    PendingConstant& pending, ConstantMaterializationResult& result) {
    if (!pending.active) return;
    if (pending.num_parts < min_parts_) {
        pending.active = false;
        return;
    }

    MaterializedConstant mc;
    mc.value = pending.value;
    mc.dst_reg = pending.dst_reg;
    mc.first_inst_id = pending.first_inst_id;
    mc.last_inst_id = pending.last_inst_id;
    mc.pc_first = pending.pc_first;
    mc.pc_last = pending.pc_last;
    mc.num_parts = pending.num_parts;
    mc.known_match = lookup(pending.value);

    result.constants.push_back(std::move(mc));

    pending.active = false;
}

// ─── Main pass execution ──────────────────────────────────────────────────

PassResult ConstantMaterializationPass::run(PassContext& ctx) {
    build_known_db();

    ConstantMaterializationResult result;

    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();

    const auto& range = ctx.range();
    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    ctx.progress(0.0f, "ConstMat: scanning trace for movz+movk sequences...");

    // Track pending constants per register (x0-x30, 31 registers)
    std::array<PendingConstant, 31> pending{};

    uint64_t inst_id = 0;
    uint64_t processed = 0;
    const uint64_t total = end - start;
    const uint64_t progress_interval = std::max(total / 100, uint64_t(1));

    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        if (inst_id < start) { inst_id++; continue; }

        auto inst = rec.as_inst();
        auto opcode_opt = code_table.opcode_at(inst.pc);

        if (opcode_opt) {
            uint32_t opcode = *opcode_opt;

            // Check for MOVZ
            auto movz = decode_movz(opcode);
            if (movz && movz->rd < 31) {
                uint8_t rd = movz->rd;

                // A new MOVZ on this register: flush any previous pending
                flush_pending(pending[rd], result);

                // Start a new pending constant
                auto& p = pending[rd];
                p.active = true;
                p.dst_reg = rd;
                p.value = static_cast<uint64_t>(movz->imm16) << (movz->hw * 16);
                p.first_inst_id = inst_id;
                p.last_inst_id = inst_id;
                p.pc_first = inst.pc;
                p.pc_last = inst.pc;
                p.num_parts = 1;
                p.shift_mask = 1u << movz->hw;
            } else {
                // Check for MOVK
                auto movk = decode_movk(opcode);
                if (movk && movk->rd < 31) {
                    uint8_t rd = movk->rd;
                    auto& p = pending[rd];

                    if (p.active && p.dst_reg == rd) {
                        // Continue building the constant: set this 16-bit slot
                        uint8_t hw = movk->hw;
                        uint64_t slot_mask = 0xFFFFULL << (hw * 16);
                        p.value = (p.value & ~slot_mask) |
                                  (static_cast<uint64_t>(movk->imm16) << (hw * 16));
                        p.last_inst_id = inst_id;
                        p.pc_last = inst.pc;
                        p.num_parts++;
                        p.shift_mask |= 1u << hw;
                    }
                    // If no active pending, this MOVK is modifying a register
                    // loaded some other way — ignore it.
                } else {
                    // Any other instruction: flush tracking state as needed.
                    auto& decoder = ctx.decoder();
                    auto decoded = decoder.decode(inst.pc, opcode);
                    if (decoded) {
                        // ── Function boundary: flush ALL pending constants ────
                        //
                        // A BL/BLR (call) or RET (return) marks a function
                        // boundary.  Any movz/movk sequence that spans this
                        // boundary is NOT a valid single constant materialization:
                        // the sequence belongs to two different execution contexts.
                        //
                        // Flushing all pending slots here eliminates the class of
                        // false positives where funcA's MOVZ and funcB's MOVK are
                        // erroneously spliced into one constant.
                        //
                        // We use the decoded mnemonic (already in Capstone's cache)
                        // so there is no extra decode cost beyond what was already
                        // needed for the regs_written check below.
                        std::string_view mn = decoded->mnemonic_sv();
                        bool is_boundary =
                            mn == "bl"    || mn == "blr"   ||
                            mn == "blraa" || mn == "blrab" ||
                            mn == "blraaz"|| mn == "blrabz"||
                            mn == "ret"   || mn == "retaa" || mn == "retab";

                        if (is_boundary) {
                            // Flush every active pending slot unconditionally.
                            for (auto& p : pending) {
                                flush_pending(p, result);
                            }
                        } else {
                            // Non-boundary instruction that writes to a tracked
                            // register: flush only those specific slots.
                            for (uint8_t w = 0; w < decoded->regs_written_count; w++) {
                                uint8_t wr = decoded->regs_written[w];
                                if (wr < 31 && pending[wr].active) {
                                    flush_pending(pending[wr], result);
                                }
                            }
                        }
                    }
                }
            }
        }

        inst_id++;
        processed++;
        if (processed % progress_interval == 0) {
            ctx.progress(static_cast<float>(processed) / total,
                         fmt::format("ConstMat: {}/{} instructions, {} constants found",
                                     processed, total, result.constants.size()));
        }
        if (ctx.cancelled()) break;
    }

    // Flush any remaining pending constants
    for (auto& p : pending) {
        flush_pending(p, result);
    }

    // Sort by first_inst_id
    std::sort(result.constants.begin(), result.constants.end(),
              [](const MaterializedConstant& a, const MaterializedConstant& b) {
                  return a.first_inst_id < b.first_inst_id;
              });

    // Build indices
    build_indices(result);

    ctx.progress(1.0f, fmt::format("ConstMat: {} constants found ({} identified as known)",
                                    result.total(), result.identified_count()));

    return PassResult::success(std::move(result));
}

// ─── Build by_algorithm index ─────────────────────────────────────────────

void ConstantMaterializationPass::build_indices(ConstantMaterializationResult& result) {
    result.identified_indices.clear();
    result.by_algorithm.clear();

    for (size_t i = 0; i < result.constants.size(); i++) {
        const auto& c = result.constants[i];
        if (c.known_match) {
            result.identified_indices.push_back(i);
            result.by_algorithm[c.known_match->algorithm].push_back(i);
        }
    }
}

}  // namespace tenet

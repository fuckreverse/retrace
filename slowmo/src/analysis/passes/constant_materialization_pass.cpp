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

    // ── SHA-256 round constants K[16..63] ─────────────────────────────────
    static const uint32_t sha256_k_rest[] = {
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    for (int i = 0; i < 48; i++) {
        add(sha256_k_rest[i],
            fmt::format("SHA256_K{}", i + 16).c_str(),
            "SHA-256",
            fmt::format("Round constant K[{}]", i + 16).c_str(),
            true);
    }

    // ── SHA-384 initial hash values (different from SHA-512) ──────────────
    add(0xcbbb9d5dc1059ed8ULL, "SHA384_H0", "SHA-384", "Initial hash value H0");
    add(0x629a292a367cd507ULL, "SHA384_H1", "SHA-384", "Initial hash value H1");
    add(0x9159015a3070dd17ULL, "SHA384_H2", "SHA-384", "Initial hash value H2");
    add(0x152fecd8f70e5939ULL, "SHA384_H3", "SHA-384", "Initial hash value H3");
    add(0x67332667ffc00b31ULL, "SHA384_H4", "SHA-384", "Initial hash value H4");
    add(0x8eb44a8768581511ULL, "SHA384_H5", "SHA-384", "Initial hash value H5");
    add(0xdb0c2e0d64f98fa7ULL, "SHA384_H6", "SHA-384", "Initial hash value H6");
    add(0x47b5481dbefa4fa4ULL, "SHA384_H7", "SHA-384", "Initial hash value H7");

    // ── SHA-512 round constants K[0..79] ──────────────────────────────────
    static const uint64_t sha512_k[] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
        0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
        0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
        0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
        0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
        0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
        0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
        0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
        0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
        0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
        0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
        0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
        0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
        0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
        0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
        0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
        0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
        0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
        0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
        0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
        0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
    };
    for (int i = 0; i < 80; i++) {
        add(sha512_k[i],
            fmt::format("SHA512_K{}", i).c_str(),
            "SHA-512",
            fmt::format("Round constant K[{}]", i).c_str());
    }

    // ── MD5 sine table T[9..64] ───────────────────────────────────────────
    static const uint32_t md5_t_rest[] = {
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    };
    for (int i = 0; i < 56; i++) {
        add(md5_t_rest[i],
            fmt::format("MD5_T{}", i + 9).c_str(),
            "MD5",
            fmt::format("Sine table T[{}]", i + 9).c_str(),
            true);
    }

    // ── SM4 constant key CK[4..31] ───────────────────────────────────────
    static const uint32_t sm4_ck_rest[] = {
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
    };
    for (int i = 0; i < 28; i++) {
        add(sm4_ck_rest[i],
            fmt::format("SM4_CK{}", i + 4).c_str(),
            "SM4",
            fmt::format("Constant key CK[{}]", i + 4).c_str(),
            true);
    }

    // ── Keccak/SHA-3 round constants (24 rounds) ──────────────────────────
    static const uint64_t keccak_rc[] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
    };
    for (int i = 0; i < 24; i++) {
        add(keccak_rc[i],
            fmt::format("KECCAK_RC{}", i).c_str(),
            "SHA-3/Keccak",
            fmt::format("Round constant iota[{}]", i).c_str());
    }

    // ── SipHash IV constants ──────────────────────────────────────────────
    add(0x736f6d6570736575ULL, "SIPHASH_IV0", "SipHash", "IV 'somepseu'");
    add(0x646f72616e646f6dULL, "SIPHASH_IV1", "SipHash", "IV 'dorandom'");
    add(0x6c7967656e657261ULL, "SIPHASH_IV2", "SipHash", "IV 'lygenera'");
    add(0x7465646279746573ULL, "SIPHASH_IV3", "SipHash", "IV 'tedbytes'");

    // ── HMAC padding constants ────────────────────────────────────────────
    add(0x36363636, "HMAC_IPAD", "HMAC", "Inner padding (ipad) repeated", true);
    add(0x5c5c5c5c, "HMAC_OPAD", "HMAC", "Outer padding (opad) repeated", true);
    add(0x3636363636363636ULL, "HMAC_IPAD64", "HMAC", "Inner padding (ipad) 64-bit");
    add(0x5c5c5c5c5c5c5c5cULL, "HMAC_OPAD64", "HMAC", "Outer padding (opad) 64-bit");

    // ── Poly1305 clamp mask ───────────────────────────────────────────────
    add(0x0ffffffc0ffffffcULL, "POLY1305_CLAMP", "Poly1305", "Clamp mask (low 64 bits)");
    add(0x0ffffffc0fffffffULL, "POLY1305_CLAMP_HI", "Poly1305", "Clamp mask (high 64 bits)");

    // ── GCM/GHASH polynomial ──────────────────────────────────────────────
    add(0xE1000000, "GCM_POLY", "GCM", "Irreducible polynomial (0xE1 << 24)", true);
    add(0x00000000000000E1ULL, "GCM_POLY64", "GCM", "Irreducible polynomial (64-bit)");
    add(0xC200000000000000ULL, "GCM_POLY_REV", "GCM", "Reversed polynomial for PMULL");

    // ── RIPEMD-160 initial values ─────────────────────────────────────────
    // (Same as MD5/SHA-1: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, already registered)
    add(0xC3D2E1F0, "RIPEMD160_H4", "RIPEMD-160", "Initial hash value H4", true);

    // ── Whirlpool round constants ─────────────────────────────────────────
    add(0x1823c6e887b8014fULL, "WHIRLPOOL_RC0", "Whirlpool", "Round constant RC[0]");
    add(0x36a6d2f5796f9152ULL, "WHIRLPOOL_RC1", "Whirlpool", "Round constant RC[1]");
    add(0x60bc9b8ea30c7b35ULL, "WHIRLPOOL_RC2", "Whirlpool", "Round constant RC[2]");
    add(0x1de0d7c22e4bfe57ULL, "WHIRLPOOL_RC3", "Whirlpool", "Round constant RC[3]");
    add(0x157737e59ff04adaULL, "WHIRLPOOL_RC4", "Whirlpool", "Round constant RC[4]");
    add(0x58c9290ab1a06b85ULL, "WHIRLPOOL_RC5", "Whirlpool", "Round constant RC[5]");
    add(0xbd5d10f4cb3e0567ULL, "WHIRLPOOL_RC6", "Whirlpool", "Round constant RC[6]");
    add(0xe427418ba77d95d8ULL, "WHIRLPOOL_RC7", "Whirlpool", "Round constant RC[7]");
    add(0xfbee7c66dd17479eULL, "WHIRLPOOL_RC8", "Whirlpool", "Round constant RC[8]");
    add(0xca2dbf07ad5a8333ULL, "WHIRLPOOL_RC9", "Whirlpool", "Round constant RC[9]");

    // ── Camellia sigma constants ──────────────────────────────────────────
    add(0xA09E667F3BCC908BULL, "CAMELLIA_SIGMA1", "Camellia", "Sigma constant 1");
    add(0xB67AE8584CAA73B2ULL, "CAMELLIA_SIGMA2", "Camellia", "Sigma constant 2");
    add(0xC6EF372FE94F82BEULL, "CAMELLIA_SIGMA3", "Camellia", "Sigma constant 3");
    add(0x54FF53A5F1D36F1CULL, "CAMELLIA_SIGMA4", "Camellia", "Sigma constant 4");
    add(0x10E527FADE682D1DULL, "CAMELLIA_SIGMA5", "Camellia", "Sigma constant 5");
    add(0xB05688C2B3E6C1FDULL, "CAMELLIA_SIGMA6", "Camellia", "Sigma constant 6");

    // ── ECDSA P-256 curve parameters (64-bit fragments) ───────────────────
    add(0xFFFFFFFF00000001ULL, "P256_P_HI", "ECDSA-P256", "Prime p high 64 bits");
    add(0x0000000000000000ULL, "P256_P_MID", "ECDSA-P256", "Prime p mid (skip, too common)");
    add(0x00000000FFFFFFFFULL, "P256_P_LO", "ECDSA-P256", "Prime p low fragment");
    add(0xFFFFFFFF00000000ULL, "P256_A", "ECDSA-P256", "Curve param a = p-3 (high)");
    add(0x5AC635D8AA3A93E7ULL, "P256_B_HI", "ECDSA-P256", "Curve param b (high 64)");

    // ── Ed25519 constants ─────────────────────────────────────────────────
    add(0x75EB4DCA135978A3ULL, "ED25519_D_LO", "Ed25519", "Curve constant d (low 64 bits)");
    add(0x00000000000014DEULL, "ED25519_COFACTOR", "Ed25519", "Cofactor value");

    // ── ZUC (Chinese stream cipher) constants ─────────────────────────────
    add(0x44D7, "ZUC_D1", "ZUC", "Linear constant d1", true);
    add(0x26BC, "ZUC_D2", "ZUC", "Linear constant d2", true);
    add(0x626B, "ZUC_D3", "ZUC", "Linear constant d3", true);
    add(0x135E, "ZUC_D4", "ZUC", "Linear constant d4", true);
    add(0x5789, "ZUC_D5", "ZUC", "Linear constant d5", true);
    add(0x35E2, "ZUC_D6", "ZUC", "Linear constant d6", true);
    add(0x7135, "ZUC_D7", "ZUC", "Linear constant d7", true);
    add(0x09AF, "ZUC_D8", "ZUC", "Linear constant d8", true);

    // ── Salsa20 tau constant (16-byte key variant) ────────────────────────
    add(0x61707865, "SALSA20_TAU0", "Salsa20", "Tau 'expa' (same as ChaCha)", true);
    add(0x3120646e, "SALSA20_TAU1", "Salsa20", "Tau 'nd 1'", true);
    add(0x79622d36, "SALSA20_TAU2", "Salsa20", "Tau '6-by'", true);
    add(0x6b206574, "SALSA20_TAU3", "Salsa20", "Tau 'te k' (same as ChaCha)", true);

    // ── Blowfish P-array [4..17] ──────────────────────────────────────────
    add(0xA4093822, "BF_P4",  "Blowfish", "P-array P[4]", true);
    add(0x299F31D0, "BF_P5",  "Blowfish", "P-array P[5]", true);
    add(0x082EFA98, "BF_P6",  "Blowfish", "P-array P[6]", true);
    add(0xEC4E6C89, "BF_P7",  "Blowfish", "P-array P[7]", true);
    add(0x452821E6, "BF_P8",  "Blowfish", "P-array P[8]", true);
    add(0x38D01377, "BF_P9",  "Blowfish", "P-array P[9]", true);
    add(0xBE5466CF, "BF_P10", "Blowfish", "P-array P[10]", true);
    add(0x34E90C6C, "BF_P11", "Blowfish", "P-array P[11]", true);
    add(0xC0AC29B7, "BF_P12", "Blowfish", "P-array P[12]", true);
    add(0xC97C50DD, "BF_P13", "Blowfish", "P-array P[13]", true);
    add(0x3F84D5B5, "BF_P14", "Blowfish", "P-array P[14]", true);
    add(0xB5470917, "BF_P15", "Blowfish", "P-array P[15]", true);
    add(0x9216D5D9, "BF_P16", "Blowfish", "P-array P[16]", true);
    add(0x8979FB1B, "BF_P17", "Blowfish", "P-array P[17]", true);

    // ── DES initial/final permutation constants ───────────────────────────
    add(0x0F0F0F0F, "DES_MASK_NIBBLE", "DES", "Nibble mask for IP/FP", true);
    add(0x00FF00FF, "DES_MASK_BYTE", "DES", "Byte mask for IP/FP", true);
    add(0x33333333, "DES_MASK_2BIT", "DES", "2-bit group mask for IP/FP", true);
    add(0x55555555, "DES_MASK_BIT", "DES", "Bit interleave mask for IP/FP", true);

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

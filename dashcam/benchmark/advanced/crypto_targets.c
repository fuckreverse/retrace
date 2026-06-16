/*
 * crypto_targets.c — Group A: Production Crypto Algorithm Implementations
 *
 * All algorithms are CORRECT, COMPLETE, and self-contained.
 * No external crypto libraries are used.
 *
 * References:
 *   - AES: FIPS 197
 *   - SHA-256: FIPS 180-4
 *   - ChaCha20: RFC 7539
 *   - XTEA: Needham & Wheeler, 1997
 *   - SM4: GB/T 32907-2016
 *   - HMAC: RFC 2104
 */

#include "advanced_targets.h"
#include <string.h>

#define NOINLINE __attribute__((noinline))

/* ═══════════════════════════════════════════════════════════════════════════
 * AES-128 Constants and Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t aes_rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* Hardcoded AES-128 key (from FIPS 197 Appendix A example) */
static const uint8_t aes_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

/* xtime: multiply by 2 in GF(2^8) */
static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static NOINLINE void aes_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = aes_sbox[state[i]];
    }
}

static NOINLINE void aes_shift_rows(uint8_t state[16]) {
    uint8_t tmp;

    /* Row 1: shift left by 1 */
    tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    /* Row 2: shift left by 2 */
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    /* Row 3: shift left by 3 */
    tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp;
}

static NOINLINE void aes_mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = state[c];
        uint8_t a1 = state[c + 1];
        uint8_t a2 = state[c + 2];
        uint8_t a3 = state[c + 3];

        uint8_t t = a0 ^ a1 ^ a2 ^ a3;
        state[c]     = a0 ^ xtime(a0 ^ a1) ^ t;
        state[c + 1] = a1 ^ xtime(a1 ^ a2) ^ t;
        state[c + 2] = a2 ^ xtime(a2 ^ a3) ^ t;
        state[c + 3] = a3 ^ xtime(a3 ^ a0) ^ t;
    }
}

static NOINLINE void aes_add_round_key(uint8_t state[16], const uint8_t *round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

static NOINLINE void aes_key_expansion(const uint8_t key[16], uint8_t round_keys[176]) {
    uint8_t temp[4];

    /* First round key is the key itself */
    memcpy(round_keys, key, 16);

    for (int i = 4; i < 44; i++) {
        temp[0] = round_keys[(i - 1) * 4 + 0];
        temp[1] = round_keys[(i - 1) * 4 + 1];
        temp[2] = round_keys[(i - 1) * 4 + 2];
        temp[3] = round_keys[(i - 1) * 4 + 3];

        if (i % 4 == 0) {
            /* RotWord */
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            /* SubWord */
            temp[0] = aes_sbox[temp[0]];
            temp[1] = aes_sbox[temp[1]];
            temp[2] = aes_sbox[temp[2]];
            temp[3] = aes_sbox[temp[3]];

            /* XOR with Rcon */
            temp[0] ^= aes_rcon[i / 4 - 1];
        }

        round_keys[i * 4 + 0] = round_keys[(i - 4) * 4 + 0] ^ temp[0];
        round_keys[i * 4 + 1] = round_keys[(i - 4) * 4 + 1] ^ temp[1];
        round_keys[i * 4 + 2] = round_keys[(i - 4) * 4 + 2] ^ temp[2];
        round_keys[i * 4 + 3] = round_keys[(i - 4) * 4 + 3] ^ temp[3];
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * target_aes128_encrypt
 * ═══════════════════════════════════════════════════════════════════════════ */

NOINLINE uint64_t target_aes128_encrypt(uint64_t seed) {
    uint8_t state[16];
    uint8_t round_keys[176];

    /* Derive plaintext from seed */
    for (int i = 0; i < 16; i++) {
        state[i] = (uint8_t)((seed >> ((i % 8) * 8)) ^ (uint8_t)i);
    }

    /* Key expansion */
    aes_key_expansion(aes_key, round_keys);

    /* Initial AddRoundKey */
    aes_add_round_key(state, round_keys);

    /* Rounds 1-9 */
    for (int round = 1; round <= 9; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, round_keys + round * 16);
    }

    /* Round 10 (no MixColumns) */
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, round_keys + 160);

    /* Return checksum of ciphertext */
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        result ^= ((uint64_t)state[i]) << ((i % 8) * 8);
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * target_aes128_keyexp
 * ═══════════════════════════════════════════════════════════════════════════ */

NOINLINE uint64_t target_aes128_keyexp(uint64_t seed) {
    uint8_t key[16];
    uint8_t round_keys[176];

    /* First 8 bytes from seed, last 8 bytes from constant */
    for (int i = 0; i < 8; i++) {
        key[i] = (uint8_t)(seed >> (i * 8));
    }
    for (int i = 8; i < 16; i++) {
        key[i] = (uint8_t)(0xA5 ^ i);
    }

    aes_key_expansion(key, round_keys);

    /* Return checksum of all 176 bytes of round keys */
    uint64_t result = 0;
    for (int i = 0; i < 176; i++) {
        result ^= ((uint64_t)round_keys[i]) << ((i % 8) * 8);
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ChaCha20 Constants and Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static NOINLINE void chacha20_quarter_round(uint32_t *a, uint32_t *b,
                                            uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * target_chacha20_block
 * ═══════════════════════════════════════════════════════════════════════════ */

NOINLINE uint64_t target_chacha20_block(uint64_t seed) {
    /* "expand 32-byte k" constant */
    static const uint32_t sigma[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    uint32_t state[16];
    uint32_t working[16];

    /* Constants */
    state[0] = sigma[0];
    state[1] = sigma[1];
    state[2] = sigma[2];
    state[3] = sigma[3];

    /* Key (256-bit, derived from constants + seed) */
    state[4]  = 0x03020100 ^ (uint32_t)(seed);
    state[5]  = 0x07060504 ^ (uint32_t)(seed >> 32);
    state[6]  = 0x0b0a0908 ^ (uint32_t)(seed);
    state[7]  = 0x0f0e0d0c ^ (uint32_t)(seed >> 32);
    state[8]  = 0x13121110 ^ (uint32_t)(seed);
    state[9]  = 0x17161514 ^ (uint32_t)(seed >> 32);
    state[10] = 0x1b1a1918 ^ (uint32_t)(seed);
    state[11] = 0x1f1e1d1c ^ (uint32_t)(seed >> 32);

    /* Counter */
    state[12] = 1;

    /* Nonce (96-bit, from seed) */
    state[13] = (uint32_t)(seed);
    state[14] = (uint32_t)(seed >> 32);
    state[15] = (uint32_t)(seed ^ 0xDEADBEEF);

    /* Copy state to working buffer */
    memcpy(working, state, 64);

    /* 20 rounds (10 double-rounds) */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        chacha20_quarter_round(&working[0], &working[4], &working[8],  &working[12]);
        chacha20_quarter_round(&working[1], &working[5], &working[9],  &working[13]);
        chacha20_quarter_round(&working[2], &working[6], &working[10], &working[14]);
        chacha20_quarter_round(&working[3], &working[7], &working[11], &working[15]);
        /* Diagonal rounds */
        chacha20_quarter_round(&working[0], &working[5], &working[10], &working[15]);
        chacha20_quarter_round(&working[1], &working[6], &working[11], &working[12]);
        chacha20_quarter_round(&working[2], &working[7], &working[8],  &working[13]);
        chacha20_quarter_round(&working[3], &working[4], &working[9],  &working[14]);
    }

    /* Add original state back */
    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
    }

    /* Return checksum of 64-byte output */
    uint64_t result = 0;
    uint8_t *output = (uint8_t *)working;
    for (int i = 0; i < 64; i++) {
        result ^= ((uint64_t)output[i]) << ((i % 8) * 8);
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SHA-256 Constants and Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t sha256_h0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static inline uint32_t sha256_rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sha256_bsig0(uint32_t x) {
    return sha256_rotr(x, 2) ^ sha256_rotr(x, 13) ^ sha256_rotr(x, 22);
}

static inline uint32_t sha256_bsig1(uint32_t x) {
    return sha256_rotr(x, 6) ^ sha256_rotr(x, 11) ^ sha256_rotr(x, 25);
}

static inline uint32_t sha256_ssig0(uint32_t x) {
    return sha256_rotr(x, 7) ^ sha256_rotr(x, 18) ^ (x >> 3);
}

static inline uint32_t sha256_ssig1(uint32_t x) {
    return sha256_rotr(x, 17) ^ sha256_rotr(x, 19) ^ (x >> 10);
}

static NOINLINE void sha256_compress_block(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, hv;

    /* Prepare message schedule */
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = sha256_ssig1(w[i - 2]) + w[i - 7] +
               sha256_ssig0(w[i - 15]) + w[i - 16];
    }

    /* Initialize working variables */
    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hv = h[7];

    /* 64 rounds */
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hv + sha256_bsig1(e) + sha256_ch(e, f, g) + sha256_k[i] + w[i];
        uint32_t t2 = sha256_bsig0(a) + sha256_maj(a, b, c);
        hv = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Add compressed chunk to hash value */
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hv;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * target_sha256_compress
 * ═══════════════════════════════════════════════════════════════════════════ */

NOINLINE uint64_t target_sha256_compress(uint64_t seed) {
    uint8_t block[64];
    uint32_t h[8];

    /* Fill block from seed */
    for (int i = 0; i < 64; i++) {
        block[i] = (uint8_t)((seed >> ((i % 8) * 8)) ^ (uint8_t)(i * 0x9E));
    }

    /* Initialize hash state */
    memcpy(h, sha256_h0, 32);

    /* Compress one block */
    sha256_compress_block(h, block);

    /* Return low 64 bits of hash state */
    return ((uint64_t)h[0] << 32) | (uint64_t)h[1];
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SHA-256 full hash (for HMAC)
 * ═══════════════════════════════════════════════════════════════════════════ */

static NOINLINE void sha256_full(const uint8_t *msg, size_t total_len, uint8_t out[32]) {
    uint32_t h[8];
    uint8_t block[64];
    size_t processed = 0;

    memcpy(h, sha256_h0, 32);

    /* Process full 64-byte blocks */
    while (total_len - processed >= 64) {
        sha256_compress_block(h, msg + processed);
        processed += 64;
    }

    /* Final block with padding */
    size_t remaining = total_len - processed;
    memset(block, 0, 64);
    memcpy(block, msg + processed, remaining);
    block[remaining] = 0x80;

    if (remaining >= 56) {
        sha256_compress_block(h, block);
        memset(block, 0, 64);
    }

    /* Append bit length (big-endian 64-bit) */
    uint64_t bit_len = (uint64_t)total_len * 8;
    block[56] = (uint8_t)(bit_len >> 56);
    block[57] = (uint8_t)(bit_len >> 48);
    block[58] = (uint8_t)(bit_len >> 40);
    block[59] = (uint8_t)(bit_len >> 32);
    block[60] = (uint8_t)(bit_len >> 24);
    block[61] = (uint8_t)(bit_len >> 16);
    block[62] = (uint8_t)(bit_len >> 8);
    block[63] = (uint8_t)(bit_len);
    sha256_compress_block(h, block);

    /* Output hash (big-endian) */
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * target_hmac_sha256
 * ═══════════════════════════════════════════════════════════════════════════ */

NOINLINE uint64_t target_hmac_sha256(uint64_t seed) {
    uint8_t key[32];
    uint8_t msg[32];
    uint8_t ipad[64 + 32]; /* inner: (key XOR ipad) || message */
    uint8_t opad[64 + 32]; /* outer: (key XOR opad) || inner_hash */
    uint8_t inner_hash[32];
    uint8_t outer_hash[32];

    /* Derive key (32 bytes) and message (32 bytes) from seed */
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)((seed >> ((i % 8) * 8)) ^ (uint8_t)(i * 0x37));
        msg[i] = (uint8_t)((seed >> ((i % 8) * 8)) ^ (uint8_t)(i * 0xB3));
    }

    /* HMAC: H((K XOR opad) || H((K XOR ipad) || msg))
     * Key is 32 bytes, block size is 64, so key is used as-is (zero-padded to 64) */

    /* Compute inner hash: SHA256((K ^ ipad) || msg) */
    for (int i = 0; i < 64; i++) {
        if (i < 32)
            ipad[i] = key[i] ^ 0x36;
        else
            ipad[i] = 0x00 ^ 0x36;
    }
    memcpy(ipad + 64, msg, 32);
    sha256_full(ipad, 96, inner_hash);

    /* Compute outer hash: SHA256((K ^ opad) || inner_hash) */
    for (int i = 0; i < 64; i++) {
        if (i < 32)
            opad[i] = key[i] ^ 0x5c;
        else
            opad[i] = 0x00 ^ 0x5c;
    }
    memcpy(opad + 64, inner_hash, 32);
    sha256_full(opad, 96, outer_hash);

    /* Return low 64 bits */
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= ((uint64_t)outer_hash[i]) << (i * 8);
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XTEA Constants and Implementation
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Hardcoded XTEA key */
static const uint32_t xtea_key[4] = {
    0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE
};

/* ═══════════════════════════════════════════════════════════════════════════
 * target_xtea64
 * ═══════════════════════════════════════════════════════════════════════════ */

NOINLINE uint64_t target_xtea64(uint64_t seed) {
    uint32_t v0 = (uint32_t)(seed);
    uint32_t v1 = (uint32_t)(seed >> 32);
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9;

    /* 64 rounds (32 cycles, each cycle does 2 Feistel rounds) */
    for (int i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + xtea_key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + xtea_key[(sum >> 11) & 3]);
    }

    return ((uint64_t)v1 << 32) | (uint64_t)v0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SM4 Constants and Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static const uint8_t sm4_sbox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
    0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
    0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
    0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
    0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
    0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
    0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
    0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
    0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
    0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
    0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
    0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

/* SM4 system parameter FK */
static const uint32_t sm4_fk[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

/* SM4 constant key CK */
static const uint32_t sm4_ck[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

/* Hardcoded SM4 key */
static const uint8_t sm4_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static inline uint32_t sm4_rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/* SM4 non-linear transformation tau (S-Box substitution on each byte) */
static NOINLINE uint32_t sm4_tau(uint32_t A) {
    uint8_t a0 = (uint8_t)(A >> 24);
    uint8_t a1 = (uint8_t)(A >> 16);
    uint8_t a2 = (uint8_t)(A >> 8);
    uint8_t a3 = (uint8_t)(A);
    return ((uint32_t)sm4_sbox[a0] << 24) |
           ((uint32_t)sm4_sbox[a1] << 16) |
           ((uint32_t)sm4_sbox[a2] << 8) |
           ((uint32_t)sm4_sbox[a3]);
}

/* SM4 linear transformation L (for encryption) */
static inline uint32_t sm4_L(uint32_t B) {
    return B ^ sm4_rotl32(B, 2) ^ sm4_rotl32(B, 10) ^
           sm4_rotl32(B, 18) ^ sm4_rotl32(B, 24);
}

/* SM4 linear transformation L' (for key expansion) */
static inline uint32_t sm4_L_prime(uint32_t B) {
    return B ^ sm4_rotl32(B, 13) ^ sm4_rotl32(B, 23);
}

/* SM4 round function T = L(tau(A)) */
static NOINLINE uint32_t sm4_T(uint32_t A) {
    return sm4_L(sm4_tau(A));
}

/* SM4 key expansion round function T' = L'(tau(A)) */
static NOINLINE uint32_t sm4_T_prime(uint32_t A) {
    return sm4_L_prime(sm4_tau(A));
}

static NOINLINE void sm4_key_expansion(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[4];
    uint32_t MK[4];

    /* Load key as big-endian words */
    for (int i = 0; i < 4; i++) {
        MK[i] = ((uint32_t)key[i * 4] << 24) |
                ((uint32_t)key[i * 4 + 1] << 16) |
                ((uint32_t)key[i * 4 + 2] << 8) |
                ((uint32_t)key[i * 4 + 3]);
    }

    /* K = MK XOR FK */
    K[0] = MK[0] ^ sm4_fk[0];
    K[1] = MK[1] ^ sm4_fk[1];
    K[2] = MK[2] ^ sm4_fk[2];
    K[3] = MK[3] ^ sm4_fk[3];

    /* Generate 32 round keys */
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = K[1] ^ K[2] ^ K[3] ^ sm4_ck[i];
        rk[i] = K[0] ^ sm4_T_prime(tmp);
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = rk[i];
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * target_sm4_encrypt
 * ═══════════════════════════════════════════════════════════════════════════ */

NOINLINE uint64_t target_sm4_encrypt(uint64_t seed) {
    uint32_t X[4];
    uint32_t rk[32];
    uint8_t plaintext[16];
    uint8_t ciphertext[16];

    /* Derive plaintext from seed */
    for (int i = 0; i < 16; i++) {
        plaintext[i] = (uint8_t)((seed >> ((i % 8) * 8)) ^ (uint8_t)(i * 0x5A));
    }

    /* Load plaintext as big-endian words */
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)plaintext[i * 4] << 24) |
               ((uint32_t)plaintext[i * 4 + 1] << 16) |
               ((uint32_t)plaintext[i * 4 + 2] << 8) |
               ((uint32_t)plaintext[i * 4 + 3]);
    }

    /* Key expansion */
    sm4_key_expansion(sm4_key, rk);

    /* 32 rounds of encryption */
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = X[1] ^ X[2] ^ X[3] ^ rk[i];
        uint32_t next = X[0] ^ sm4_T(tmp);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = next;
    }

    /* Reverse order for output (R transformation) */
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[3 - i];
        ciphertext[i * 4]     = (uint8_t)(val >> 24);
        ciphertext[i * 4 + 1] = (uint8_t)(val >> 16);
        ciphertext[i * 4 + 2] = (uint8_t)(val >> 8);
        ciphertext[i * 4 + 3] = (uint8_t)(val);
    }

    /* Return checksum of 16-byte ciphertext */
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        result ^= ((uint64_t)ciphertext[i]) << ((i % 8) * 8);
    }
    return result;
}

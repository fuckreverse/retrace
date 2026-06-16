/*
 * qbditrace advanced benchmark - Group C (Real-World Scenarios) &
 *                                  Group D (Tenet Stress Tests)
 *
 * These targets simulate patterns found in actual protected iOS/Android apps
 * and push tenet's analysis passes to their limits.
 *
 * All functions are deterministic: same seed -> same output.
 */

#include "advanced_targets.h"
#include <string.h>

#define NOINLINE __attribute__((noinline))

/* ===========================================================================
 * SHA-256 implementation (used by C1, C2)
 *
 * Full 64-round compression with real K constants and initial hash values.
 * Tenet PatternPass should detect these constants.
 * =========================================================================== */

static const uint32_t sha256_K[64] = {
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

static const uint32_t sha256_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t sha256_Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t sha256_Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sha256_Sigma0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static inline uint32_t sha256_Sigma1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static inline uint32_t sha256_sigma0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static inline uint32_t sha256_sigma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

/* SHA-256 compression of a single 64-byte block. Hash state in/out via h[8]. */
static void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t W[64];
    int i;

    /* Parse block into 16 big-endian words */
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i*4] << 24) |
                ((uint32_t)block[i*4+1] << 16) |
                ((uint32_t)block[i*4+2] << 8) |
                ((uint32_t)block[i*4+3]);
    }
    /* Extend to 64 words */
    for (i = 16; i < 64; i++) {
        W[i] = sha256_sigma1(W[i-2]) + W[i-7] + sha256_sigma0(W[i-15]) + W[i-16];
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (i = 0; i < 64; i++) {
        uint32_t T1 = hh + sha256_Sigma1(e) + sha256_Ch(e, f, g) + sha256_K[i] + W[i];
        uint32_t T2 = sha256_Sigma0(a) + sha256_Maj(a, b, c);
        hh = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

/* Full SHA-256 hash of arbitrary data */
static void sha256_hash(const uint8_t *data, uint32_t len, uint8_t out[32]) {
    uint32_t h[8];
    uint8_t block[64];
    uint32_t i;

    memcpy(h, sha256_H0, sizeof(h));

    /* Process full blocks */
    uint32_t full_blocks = len / 64;
    for (i = 0; i < full_blocks; i++) {
        sha256_compress(h, data + i * 64);
    }

    /* Final block with padding */
    uint32_t remaining = len - full_blocks * 64;
    memset(block, 0, 64);
    memcpy(block, data + full_blocks * 64, remaining);
    block[remaining] = 0x80;

    if (remaining >= 56) {
        /* Need two blocks for padding */
        sha256_compress(h, block);
        memset(block, 0, 64);
    }

    /* Append length in bits (big-endian, 64-bit) */
    uint64_t bitlen = (uint64_t)len * 8;
    block[56] = (uint8_t)(bitlen >> 56);
    block[57] = (uint8_t)(bitlen >> 48);
    block[58] = (uint8_t)(bitlen >> 40);
    block[59] = (uint8_t)(bitlen >> 32);
    block[60] = (uint8_t)(bitlen >> 24);
    block[61] = (uint8_t)(bitlen >> 16);
    block[62] = (uint8_t)(bitlen >> 8);
    block[63] = (uint8_t)(bitlen);
    sha256_compress(h, block);

    /* Output hash as big-endian bytes */
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

/* HMAC-SHA256 */
static void hmac_sha256(const uint8_t *key, uint32_t key_len,
                        const uint8_t *msg, uint32_t msg_len,
                        uint8_t out[32]) {
    uint8_t k_pad[64];
    uint8_t inner_buf[64 + 256]; /* ipad || msg */
    uint8_t outer_buf[64 + 32];  /* opad || inner_hash */
    uint8_t inner_hash[32];
    uint32_t i;

    /* If key > 64 bytes, hash it first */
    uint8_t hashed_key[32];
    const uint8_t *actual_key = key;
    uint32_t actual_key_len = key_len;
    if (key_len > 64) {
        sha256_hash(key, key_len, hashed_key);
        actual_key = hashed_key;
        actual_key_len = 32;
    }

    /* Pad key to 64 bytes */
    memset(k_pad, 0, 64);
    memcpy(k_pad, actual_key, actual_key_len);

    /* Inner hash: SHA256((key XOR ipad) || msg) */
    for (i = 0; i < 64; i++) {
        inner_buf[i] = k_pad[i] ^ 0x36;
    }
    memcpy(inner_buf + 64, msg, msg_len);
    sha256_hash(inner_buf, 64 + msg_len, inner_hash);

    /* Outer hash: SHA256((key XOR opad) || inner_hash) */
    for (i = 0; i < 64; i++) {
        outer_buf[i] = k_pad[i] ^ 0x5c;
    }
    memcpy(outer_buf + 64, inner_hash, 32);
    sha256_hash(outer_buf, 64 + 32, out);
}

/* ===========================================================================
 * CRC32 table (used by C3)
 * Standard polynomial 0xEDB88320 (bit-reflected)
 * =========================================================================== */

static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91B, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D09, 0x90BF1D9F, 0x1DB71064, 0x6AB020F2,
    0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F6B5, 0x56B3C423,
    0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
    0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0D69, 0x086D3D2B,
    0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
    0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
    0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7A23, 0x5005713C, 0x270241AA,
    0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
    0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
    0x0D6D6A3E, 0x7A6A5A08, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
    0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
    0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
    0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
    0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
    0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB9, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
    0x68DDB3F6, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6B70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
    0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD706FF,
    0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

static uint32_t compute_crc32(const uint8_t *data, uint32_t len) {
    uint32_t crc = 0xFFFFFFFF;
    uint32_t i;
    for (i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

/* ===========================================================================
 * AES S-Box (used by C5, C6, D2)
 * =========================================================================== */

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

/* ===========================================================================
 * XTEA helper (used by C3, C5)
 * =========================================================================== */

static void xtea_encrypt_block(uint32_t v[2], const uint32_t key[4], uint32_t rounds) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0, delta = 0x9E3779B9;
    uint32_t i;
    for (i = 0; i < rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

/* ===========================================================================
 * Group C: Real-World Scenarios
 *
 * These simulate patterns found in actual protected mobile apps:
 *   - Key derivation chains (C1)
 *   - API request signing (C2)
 *   - Anti-tamper integrity checks (C3)
 *   - VM-based code virtualization (C4)
 *   - Layered encryption pipelines (C5)
 *   - CFF+MBA obfuscated AES (C6)
 * =========================================================================== */

/* ---------------------------------------------------------------------------
 * C1: PBKDF2-HMAC-SHA256 key derivation (100 iterations)
 *
 * Tests tenet's ability to handle long repetitive traces.
 * PatternPass should detect SHA-256 constants repeated 100x.
 * TaintPass should trace seed -> password -> derived key material.
 * --------------------------------------------------------------------------- */
NOINLINE uint64_t target_pbkdf2_sha256(uint64_t seed) {
    /* Password: 8 bytes from seed */
    uint8_t password[8];
    uint8_t salt[8];
    uint8_t U[32], T[32];
    uint32_t i, j;

    for (i = 0; i < 8; i++) {
        password[i] = (uint8_t)(seed >> (i * 8));
        salt[i] = (uint8_t)(~seed >> (i * 8));
    }

    /* PBKDF2: derive 32 bytes (1 block), 100 iterations */
    /* U_1 = HMAC(password, salt || INT(1)) */
    uint8_t salt_block[12]; /* salt (8) + block counter (4, big-endian) */
    memcpy(salt_block, salt, 8);
    salt_block[8] = 0;
    salt_block[9] = 0;
    salt_block[10] = 0;
    salt_block[11] = 1;

    hmac_sha256(password, 8, salt_block, 12, U);
    memcpy(T, U, 32);

    /* U_2 ... U_100: each U_i = HMAC(password, U_{i-1}), T ^= U_i */
    for (i = 1; i < 100; i++) {
        hmac_sha256(password, 8, U, 32, U);
        for (j = 0; j < 32; j++) {
            T[j] ^= U[j];
        }
    }

    /* Return low 64 bits of derived key */
    uint64_t result = 0;
    for (i = 0; i < 8; i++) {
        result |= (uint64_t)T[i] << (i * 8);
    }
    return result;
}

/* ---------------------------------------------------------------------------
 * C2: Request signing pipeline
 *
 * Simulates API request signing: timestamp + canonical string + HMAC.
 * Tests tenet's ability to track key material through multi-stage signing.
 * The pattern mimics cloud API authentication (AWS SigV4, etc.)
 * --------------------------------------------------------------------------- */
NOINLINE uint64_t target_request_sign(uint64_t seed) {
    /* Fixed secret key (32 bytes) - tenet should identify this as key material */
    static const uint8_t secret_key[32] = {
        0x4d, 0x79, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74,
        0x4b, 0x65, 0x79, 0x46, 0x6f, 0x72, 0x53, 0x69,
        0x67, 0x6e, 0x69, 0x6e, 0x67, 0x41, 0x50, 0x49,
        0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73
    };
    static const char hex_chars[] = "0123456789abcdef";

    /* Step 1: Generate timestamp from seed */
    uint64_t timestamp = seed ^ 0x5A5A5A5A5A5A5A5AULL;

    /* Step 2: Build canonical string */
    uint8_t canonical[128];
    uint32_t pos = 0;

    /* "GET\n/api/v1/data\n" */
    canonical[pos++] = 'G'; canonical[pos++] = 'E'; canonical[pos++] = 'T';
    canonical[pos++] = '\n';
    canonical[pos++] = '/'; canonical[pos++] = 'a'; canonical[pos++] = 'p';
    canonical[pos++] = 'i'; canonical[pos++] = '/'; canonical[pos++] = 'v';
    canonical[pos++] = '1'; canonical[pos++] = '/'; canonical[pos++] = 'd';
    canonical[pos++] = 'a'; canonical[pos++] = 't'; canonical[pos++] = 'a';
    canonical[pos++] = '\n';

    /* Timestamp as 16 hex chars */
    for (int i = 15; i >= 0; i--) {
        canonical[pos++] = (uint8_t)hex_chars[(timestamp >> (i * 4)) & 0xF];
    }
    canonical[pos++] = '\n';

    /* Body hash: SHA-256 of seed bytes */
    uint8_t body[8];
    for (int i = 0; i < 8; i++) {
        body[i] = (uint8_t)(seed >> (i * 8));
    }
    uint8_t body_hash[32];
    sha256_hash(body, 8, body_hash);

    /* Append body hash as hex string */
    for (int i = 0; i < 32; i++) {
        canonical[pos++] = (uint8_t)hex_chars[(body_hash[i] >> 4) & 0xF];
        canonical[pos++] = (uint8_t)hex_chars[body_hash[i] & 0xF];
    }

    /* Step 3: HMAC-SHA256(secret_key, canonical_string) */
    uint8_t hmac_result[32];
    hmac_sha256(secret_key, 32, canonical, pos, hmac_result);

    /* Return low 64 bits of HMAC result */
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= (uint64_t)hmac_result[i] << (i * 8);
    }
    return result;
}

/* ---------------------------------------------------------------------------
 * C3: Anti-tamper CRC self-check
 *
 * Tests pattern detection: CRC32 integrity check + conditional corruption.
 * Tenet should detect the CRC verification pattern and tamper response.
 * The function always produces a "correct" (non-corrupted) result because
 * the expected CRC is computed over the same data.
 * --------------------------------------------------------------------------- */
NOINLINE uint64_t target_antitamper_crc(uint64_t seed) {
    /* Fill 256-byte "code region" deterministically from seed via xorshift */
    uint8_t code_region[256];
    uint64_t gen = seed;
    for (int i = 0; i < 256; i++) {
        gen ^= gen << 13;
        gen ^= gen >> 7;
        gen ^= gen << 17;
        code_region[i] = (uint8_t)(gen & 0xFF);
    }

    /* Compute CRC32 over the code region */
    uint32_t crc = compute_crc32(code_region, 256);

    /* The "expected" CRC is always equal to the computed CRC because we
     * compute over data we just generated. This ensures the function ALWAYS
     * produces a correct (non-corrupted) result for any seed. */
    uint32_t expected_crc = crc;

    /* XTEA key for the final computation */
    static const uint32_t tamper_key[4] = {
        0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210
    };

    uint32_t v[2];
    v[0] = (uint32_t)seed;
    v[1] = (uint32_t)(seed >> 32);

    uint64_t result;
    if (crc == expected_crc) {
        /* Integrity check passed: normal XTEA computation */
        xtea_encrypt_block(v, tamper_key, 32);
        result = ((uint64_t)v[1] << 32) | v[0];
    } else {
        /* Tampered: corrupt output (unreachable, but pattern exists for detection) */
        xtea_encrypt_block(v, tamper_key, 32);
        result = (((uint64_t)v[1] << 32) | v[0]) ^ 0xDEADDEADDEADDEADULL;
    }
    return result;
}

/* ---------------------------------------------------------------------------
 * C4: Mini VM interpreter (8 opcodes, 128 bytecodes from seed)
 *
 * Simulates VMP-style code virtualization with a stack-based bytecode engine.
 * Tests tenet's ability to reconstruct meaningful semantics from virtualized code.
 * Each seed generates a different "program", making each trace unique.
 * --------------------------------------------------------------------------- */
NOINLINE uint64_t target_mini_vm(uint64_t seed) {
    /* VM state: 16-element stack, 16-element memory */
    uint64_t stack[16];
    uint64_t memory[16];
    int sp = 0;

    memset(stack, 0, sizeof(stack));
    memset(memory, 0, sizeof(memory));

    /* Initialize memory from seed (provides input data for LOAD operations) */
    uint64_t rng = seed;
    for (int i = 0; i < 16; i++) {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        memory[i] = rng;
    }

    /* Generate 128 bytecodes from seed using xorshift */
    uint8_t bytecodes[128];
    rng = seed ^ 0xCAFEBABEDEADBEEFULL;
    for (int i = 0; i < 128; i++) {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        bytecodes[i] = (uint8_t)(rng & 0xFF);
    }

    /* Execute bytecodes: 3-bit opcode + 5-bit immediate per byte */
    for (int pc = 0; pc < 128; pc++) {
        uint8_t insn = bytecodes[pc];
        uint8_t opcode = insn & 0x07;     /* bits [2:0] = opcode */
        uint8_t imm = (insn >> 3) & 0x1F; /* bits [7:3] = immediate */

        switch (opcode) {
            case 0: /* PUSH: push 5-bit immediate onto stack */
                if (sp < 16) stack[sp++] = (uint64_t)imm;
                break;
            case 1: /* ADD: pop 2, push sum */
                if (sp >= 2) { sp--; stack[sp-1] += stack[sp]; }
                break;
            case 2: /* XOR: pop 2, push xor */
                if (sp >= 2) { sp--; stack[sp-1] ^= stack[sp]; }
                break;
            case 3: /* MUL: pop 2, push product */
                if (sp >= 2) { sp--; stack[sp-1] *= stack[sp]; }
                break;
            case 4: /* ROT: pop 1, rotate left by 13, push */
                if (sp >= 1) {
                    uint64_t v = stack[sp-1];
                    stack[sp-1] = (v << 13) | (v >> 51);
                }
                break;
            case 5: /* DUP: duplicate top of stack */
                if (sp >= 1 && sp < 16) { stack[sp] = stack[sp-1]; sp++; }
                break;
            case 6: /* SWAP: swap top 2 elements */
                if (sp >= 2) {
                    uint64_t tmp = stack[sp-1];
                    stack[sp-1] = stack[sp-2];
                    stack[sp-2] = tmp;
                }
                break;
            case 7: /* LOAD: pop addr, push memory[addr & 0xF] */
                if (sp >= 1) {
                    uint64_t addr = stack[sp-1] & 0xF;
                    stack[sp-1] = memory[addr];
                }
                break;
        }
    }

    return (sp > 0) ? stack[sp-1] : 0;
}

/* ---------------------------------------------------------------------------
 * C5: Layered encryption (XTEA -> ChaCha20-like -> AES SubBytes+ShiftRows)
 *
 * Tests deep taint propagation through multiple crypto layers.
 * Each layer uses a distinct algorithm with its own key.
 * PatternPass should detect all three algorithm signatures.
 * --------------------------------------------------------------------------- */
NOINLINE uint64_t target_layered_crypto(uint64_t seed) {
    /* === Layer 1: XTEA encrypt (64 rounds) === */
    static const uint32_t xtea_key1[4] = {
        0x11111111, 0x22222222, 0x33333333, 0x44444444
    };
    uint32_t v[2];
    v[0] = (uint32_t)seed;
    v[1] = (uint32_t)(seed >> 32);
    xtea_encrypt_block(v, xtea_key1, 64);
    uint64_t after_xtea = ((uint64_t)v[1] << 32) | v[0];

    /* === Layer 2: ChaCha20-like quarter-round transform ===
     * Expand 64-bit value to 4x uint32, apply 8 quarter-rounds.
     * Uses real ChaCha20 constants for PatternPass detection. */
    uint32_t a = (uint32_t)(after_xtea);
    uint32_t b = (uint32_t)(after_xtea >> 32);
    uint32_t c = a ^ 0x61707865; /* "expa" */
    uint32_t d = b ^ 0x3320646E; /* "nd 3" */

    for (int i = 0; i < 8; i++) {
        /* Standard ChaCha20 quarter-round operations */
        a += b; d ^= a; d = (d << 16) | (d >> 16);
        c += d; b ^= c; b = (b << 12) | (b >> 20);
        a += b; d ^= a; d = (d << 8) | (d >> 24);
        c += d; b ^= c; b = (b << 7) | (b >> 25);
    }
    uint64_t after_chacha = ((uint64_t)b << 32) | a;
    after_chacha ^= ((uint64_t)d << 32) | c;

    /* === Layer 3: AES-like SubBytes + ShiftRows (single round) ===
     * Uses real AES S-Box for PatternPass detection. */
    uint8_t state[16];
    for (int i = 0; i < 8; i++) {
        state[i] = (uint8_t)(after_chacha >> (i * 8));
        state[i + 8] = (uint8_t)((after_chacha >> (i * 8)) ^ 0xA5);
    }

    /* SubBytes: apply real AES S-Box */
    for (int i = 0; i < 16; i++) {
        state[i] = aes_sbox[state[i]];
    }

    /* ShiftRows: treat state as 4x4 column-major matrix */
    uint8_t tmp;
    /* Row 1: shift left by 1 */
    tmp = state[1]; state[1] = state[5]; state[5] = state[9];
    state[9] = state[13]; state[13] = tmp;
    /* Row 2: shift left by 2 */
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    /* Row 3: shift left by 3 (= shift right by 1) */
    tmp = state[15]; state[15] = state[11]; state[11] = state[7];
    state[7] = state[3]; state[3] = tmp;

    /* Pack result: XOR first 8 with last 8 bytes */
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= (uint64_t)(state[i] ^ state[i + 8]) << (i * 8);
    }
    return result;
}

/* ---------------------------------------------------------------------------
 * C6: CFF-protected AES with MBA-substituted operations
 *
 * The "boss fight" - combines control flow flattening with MBA obfuscation
 * on a real AES-128 implementation. Must produce CORRECT AES output.
 *
 * CFF: while+switch dispatcher with 12 states
 * MBA: XOR replaced with (a|b)-(a&b) throughout
 * S-Box: real AES S-Box used for lookups
 *
 * Tenet must simultaneously handle:
 *   - CFGPass: reconstruct round structure from CFF trace
 *   - PatternPass: detect AES S-Box despite MBA wrapping
 *   - TaintPass: track key flow through MBA expressions
 * --------------------------------------------------------------------------- */

/* MBA-substituted XOR: a ^ b == (a | b) - (a & b) */
static inline uint8_t mba_xor8(uint8_t a, uint8_t b) {
    return (uint8_t)((a | b) - (a & b));
}

/* xtime for MixColumns (GF(2^8) multiply by 2) */
static inline uint8_t mba_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

NOINLINE uint64_t target_aes_cff_mba(uint64_t seed) {
    /* AES-128 key (FIPS-197 Appendix A example key) */
    static const uint8_t aes_key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    /* AES round constants for key expansion */
    static const uint8_t rcon[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    /* State (16 bytes) and expanded round keys (176 bytes) */
    uint8_t state[16];
    uint8_t rk[176];

    /* Initialize state from seed */
    for (int i = 0; i < 8; i++) {
        state[i] = (uint8_t)(seed >> (i * 8));
        state[i + 8] = (uint8_t)((seed >> (i * 8)) ^ 0x5A);
    }

    /* === Key Expansion (with MBA-substituted XOR) === */
    memcpy(rk, aes_key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        memcpy(temp, &rk[(i-1)*4], 4);
        if (i % 4 == 0) {
            /* RotWord + SubWord + Rcon (MBA XOR for Rcon addition) */
            uint8_t t = temp[0];
            temp[0] = mba_xor8(aes_sbox[temp[1]], rcon[i/4 - 1]);
            temp[1] = aes_sbox[temp[2]];
            temp[2] = aes_sbox[temp[3]];
            temp[3] = aes_sbox[t];
        }
        for (int j = 0; j < 4; j++) {
            rk[i*4 + j] = mba_xor8(rk[(i-4)*4 + j], temp[j]);
        }
    }

    /* === CFF Dispatcher: AES-128 encryption in a state machine ===
     * States: 0=init, 1=subbytes, 2=shiftrows, 3=mixcols,
     *         4=addroundkey, 5=final_subbytes, 6=exit
     * This creates a flat control flow graph that obscures the round structure. */
    int cff_state = 0;
    int round = 0;

    while (1) {
        switch (cff_state) {
            case 0: { /* INIT: AddRoundKey with key[0] */
                for (int i = 0; i < 16; i++) {
                    state[i] = mba_xor8(state[i], rk[i]);
                }
                round = 1;
                cff_state = 1;
                break;
            }
            case 1: { /* SubBytes (rounds 1-9) */
                for (int i = 0; i < 16; i++) {
                    /* MBA identity for index: x ^ 0 = (x|0) - (x&0) = x */
                    uint8_t idx = mba_xor8(state[i], 0);
                    state[i] = aes_sbox[idx];
                }
                cff_state = 2;
                break;
            }
            case 2: { /* ShiftRows */
                uint8_t tmp;
                /* Row 1: shift left by 1 */
                tmp = state[1]; state[1] = state[5]; state[5] = state[9];
                state[9] = state[13]; state[13] = tmp;
                /* Row 2: shift left by 2 */
                tmp = state[2]; state[2] = state[10]; state[10] = tmp;
                tmp = state[6]; state[6] = state[14]; state[14] = tmp;
                /* Row 3: shift left by 3 */
                tmp = state[15]; state[15] = state[11]; state[11] = state[7];
                state[7] = state[3]; state[3] = tmp;
                /* Route to MixColumns or directly to AddRoundKey (final round) */
                cff_state = (round < 10) ? 3 : 4;
                break;
            }
            case 3: { /* MixColumns (with MBA XOR: a^b = (a|b)-(a&b)) */
                for (int col = 0; col < 4; col++) {
                    int base = col * 4;
                    uint8_t a0 = state[base];
                    uint8_t a1 = state[base + 1];
                    uint8_t a2 = state[base + 2];
                    uint8_t a3 = state[base + 3];
                    uint8_t t = mba_xor8(mba_xor8(a0, a1), mba_xor8(a2, a3));
                    state[base]   = mba_xor8(a0, mba_xor8(mba_xtime(mba_xor8(a0, a1)), t));
                    state[base+1] = mba_xor8(a1, mba_xor8(mba_xtime(mba_xor8(a1, a2)), t));
                    state[base+2] = mba_xor8(a2, mba_xor8(mba_xtime(mba_xor8(a2, a3)), t));
                    state[base+3] = mba_xor8(a3, mba_xor8(mba_xtime(mba_xor8(a3, a0)), t));
                }
                cff_state = 4;
                break;
            }
            case 4: { /* AddRoundKey */
                for (int i = 0; i < 16; i++) {
                    state[i] = mba_xor8(state[i], rk[round * 16 + i]);
                }
                round++;
                if (round <= 9) {
                    cff_state = 1; /* Back to SubBytes for next round */
                } else if (round == 10) {
                    cff_state = 5; /* Final round: SubBytes without MixColumns */
                } else {
                    cff_state = 6; /* Done */
                }
                break;
            }
            case 5: { /* Final round SubBytes (round 10, no MixColumns) */
                for (int i = 0; i < 16; i++) {
                    state[i] = aes_sbox[state[i]];
                }
                cff_state = 2; /* ShiftRows -> AddRoundKey (round < 10 is false) */
                break;
            }
            case 6: { /* EXIT */
                goto cff_done;
            }
            default:
                goto cff_done;
        }
    }
cff_done:
    ; /* empty statement after label for C11 compatibility */

    /* Return checksum of ciphertext: XOR upper and lower halves */
    {
        uint64_t result = 0;
        for (int i = 0; i < 8; i++) {
            result |= (uint64_t)(state[i] ^ state[i + 8]) << (i * 8);
        }
        return result;
    }
}


/* ===========================================================================
 * GROUP D: TENET STRESS TESTS
 *
 * Designed to push specific tenet analysis passes to their limits.
 * Each creates extreme load on a different aspect of trace analysis.
 * =========================================================================== */

/* ---------------------------------------------------------------------------
 * D1: Branch explosion - maximum path divergence
 *
 * 10 bits -> 1024 primary paths, each with unique arithmetic.
 * 5 more bits -> 32 post-processing variants.
 * Total unique paths: 1024 x 32 = 32768.
 *
 * Stress tests CFG reconstruction (many unique edges per trace).
 * --------------------------------------------------------------------------- */
NOINLINE uint64_t target_branch_explosion(uint64_t seed) {
    uint64_t result = seed;

    /* 10 bits select primary computation path (1024 variants) */
    uint32_t path = (uint32_t)(seed & 0x3FF);

    /* Path-specific constant derived from golden ratio fractional bits */
    uint64_t path_const = 0x9E3779B97F4A7C15ULL + (uint64_t)path * 0x6A09E667F3BCC908ULL;
    result *= path_const;
    result ^= result >> 17;

    /* Path-specific rotation amount */
    uint32_t rot_amount = (path % 63) + 1;
    result = (result << rot_amount) | (result >> (64 - rot_amount));

    /* Path-specific XOR mixing */
    result ^= (uint64_t)path * 0xBB67AE8584CAA73BULL;

    /* 5 more bits select post-processing (32 variants) */
    uint32_t post = (uint32_t)((seed >> 10) & 0x1F);

    switch (post & 0x7) {
        case 0: result = result * 0xFF51AFD7ED558CCDULL; break;
        case 1: result = result ^ (result >> 33); break;
        case 2: result = result + (result << 11); break;
        case 3: result = (result << 23) | (result >> 41); break;
        case 4: result = result * 0xC4CEB9FE1A85EC53ULL; break;
        case 5: result = result ^ (result << 19); break;
        case 6: result = ~result * 0x51D7348A9B14F4A5ULL; break;
        case 7: result = result ^ (result >> 27) ^ (result >> 41); break;
    }

    /* Additional mixing from higher bits */
    if (post & 0x08) result = (result << 31) | (result >> 33);
    if (post & 0x10) result ^= 0x3C6EF372FE94F82BULL;

    return result;
}

/* ---------------------------------------------------------------------------
 * D2: Table-based AES (T-table implementation)
 *
 * Uses 4 pre-computed T-tables (each 256 x uint32_t = 1024 bytes).
 * Total table data: 4096 bytes of memory accesses per encryption.
 *
 * Stress tests memory model tracking in tenet with many distinct addresses.
 * PatternPass should detect AES despite the table-based obfuscation.
 * --------------------------------------------------------------------------- */

/* T-table computation helpers */
static inline uint8_t xtime_byte(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/* Pre-computed T-tables for table-based AES.
 * Te0[i] = { 02*S[i], S[i], S[i], 03*S[i] } as a uint32_t column
 * Te1, Te2, Te3 are byte-rotations of Te0. */
static uint32_t Te0[256];
static uint32_t Te1[256];
static uint32_t Te2[256];
static uint32_t Te3[256];
static int te_tables_init = 0;

static void init_te_tables(void) {
    if (te_tables_init) return;
    for (int i = 0; i < 256; i++) {
        uint8_t s = aes_sbox[i];
        uint8_t x2 = xtime_byte(s);
        uint8_t x3 = x2 ^ s;
        /* Te0: [x2, s, s, x3] (little-endian column) */
        Te0[i] = ((uint32_t)x2) | ((uint32_t)s << 8) |
                 ((uint32_t)s << 16) | ((uint32_t)x3 << 24);
        /* Te1: rotate Te0 left by 8 bits */
        Te1[i] = ((uint32_t)x3) | ((uint32_t)x2 << 8) |
                 ((uint32_t)s << 16) | ((uint32_t)s << 24);
        /* Te2: rotate Te0 left by 16 bits */
        Te2[i] = ((uint32_t)s) | ((uint32_t)x3 << 8) |
                 ((uint32_t)x2 << 16) | ((uint32_t)s << 24);
        /* Te3: rotate Te0 left by 24 bits */
        Te3[i] = ((uint32_t)s) | ((uint32_t)s << 8) |
                 ((uint32_t)x3 << 16) | ((uint32_t)x2 << 24);
    }
    te_tables_init = 1;
}

NOINLINE uint64_t target_aes_tablebased(uint64_t seed) {
    init_te_tables();

    /* AES-128 key */
    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const uint8_t rcon_tab[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    /* Key expansion (little-endian uint32 words) */
    uint32_t rk[44];
    for (int i = 0; i < 4; i++) {
        rk[i] = ((uint32_t)key[4*i]) | ((uint32_t)key[4*i+1] << 8) |
                ((uint32_t)key[4*i+2] << 16) | ((uint32_t)key[4*i+3] << 24);
    }
    for (int i = 4; i < 44; i++) {
        uint32_t temp = rk[i-1];
        if (i % 4 == 0) {
            temp = (temp >> 8) | (temp << 24); /* RotWord */
            temp = ((uint32_t)aes_sbox[temp & 0xFF]) |
                   ((uint32_t)aes_sbox[(temp >> 8) & 0xFF] << 8) |
                   ((uint32_t)aes_sbox[(temp >> 16) & 0xFF] << 16) |
                   ((uint32_t)aes_sbox[(temp >> 24) & 0xFF] << 24);
            temp ^= (uint32_t)rcon_tab[i/4 - 1];
        }
        rk[i] = rk[i-4] ^ temp;
    }

    /* Initialize state columns from seed + initial AddRoundKey */
    uint32_t s0 = (uint32_t)(seed) ^ rk[0];
    uint32_t s1 = (uint32_t)(seed >> 32) ^ rk[1];
    uint32_t s2 = (uint32_t)(seed ^ 0xA5A5A5A5ULL) ^ rk[2];
    uint32_t s3 = (uint32_t)((seed >> 32) ^ 0x5A5A5A5AULL) ^ rk[3];

    /* 9 main rounds using T-tables (massive memory access pattern) */
    for (int round = 1; round <= 9; round++) {
        uint32_t t0 = Te0[s0 & 0xFF] ^ Te1[(s1 >> 8) & 0xFF] ^
                      Te2[(s2 >> 16) & 0xFF] ^ Te3[(s3 >> 24) & 0xFF] ^ rk[round*4];
        uint32_t t1 = Te0[s1 & 0xFF] ^ Te1[(s2 >> 8) & 0xFF] ^
                      Te2[(s3 >> 16) & 0xFF] ^ Te3[(s0 >> 24) & 0xFF] ^ rk[round*4+1];
        uint32_t t2 = Te0[s2 & 0xFF] ^ Te1[(s3 >> 8) & 0xFF] ^
                      Te2[(s0 >> 16) & 0xFF] ^ Te3[(s1 >> 24) & 0xFF] ^ rk[round*4+2];
        uint32_t t3 = Te0[s3 & 0xFF] ^ Te1[(s0 >> 8) & 0xFF] ^
                      Te2[(s1 >> 16) & 0xFF] ^ Te3[(s2 >> 24) & 0xFF] ^ rk[round*4+3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
    uint32_t t0 = ((uint32_t)aes_sbox[s0 & 0xFF]) |
                  ((uint32_t)aes_sbox[(s1 >> 8) & 0xFF] << 8) |
                  ((uint32_t)aes_sbox[(s2 >> 16) & 0xFF] << 16) |
                  ((uint32_t)aes_sbox[(s3 >> 24) & 0xFF] << 24);
    uint32_t t1 = ((uint32_t)aes_sbox[s1 & 0xFF]) |
                  ((uint32_t)aes_sbox[(s2 >> 8) & 0xFF] << 8) |
                  ((uint32_t)aes_sbox[(s3 >> 16) & 0xFF] << 16) |
                  ((uint32_t)aes_sbox[(s0 >> 24) & 0xFF] << 24);
    uint32_t t2 = ((uint32_t)aes_sbox[s2 & 0xFF]) |
                  ((uint32_t)aes_sbox[(s3 >> 8) & 0xFF] << 8) |
                  ((uint32_t)aes_sbox[(s0 >> 16) & 0xFF] << 16) |
                  ((uint32_t)aes_sbox[(s1 >> 24) & 0xFF] << 24);
    uint32_t t3 = ((uint32_t)aes_sbox[s3 & 0xFF]) |
                  ((uint32_t)aes_sbox[(s0 >> 8) & 0xFF] << 8) |
                  ((uint32_t)aes_sbox[(s1 >> 16) & 0xFF] << 16) |
                  ((uint32_t)aes_sbox[(s2 >> 24) & 0xFF] << 24);
    s0 = t0 ^ rk[40]; s1 = t1 ^ rk[41]; s2 = t2 ^ rk[42]; s3 = t3 ^ rk[43];

    /* Return checksum of 16-byte ciphertext */
    return ((uint64_t)s0 ^ ((uint64_t)s1 << 16) ^ ((uint64_t)s2 << 32) ^ ((uint64_t)s3 << 48));
}

/* ---------------------------------------------------------------------------
 * D3: Deep call chain (50 nested function calls)
 *
 * Implemented as recursive dispatch with transform array (not 50 functions).
 * Each level applies: rotate, xor-with-constant, or multiply.
 * Call depth ~50 stress tests CallGraph pass reconstruction.
 * --------------------------------------------------------------------------- */

/* 50 level-specific constants (from digits of pi) */
static const uint64_t deep_constants[50] = {
    0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL, 0xA4093822299F31D0ULL,
    0x082EFA98EC4E6C89ULL, 0x452821E638D01377ULL, 0xBE5466CF34E90C6CULL,
    0xC0AC29B7C97C50DDULL, 0x3F84D5B5B5470917ULL, 0x9216D5D98979FB1BULL,
    0xD1310BA698DFB5ACULL, 0x2FFD72DBD01ADFB7ULL, 0xB8E1AFED6A267E96ULL,
    0xBA7C9045F12C7F99ULL, 0x24A19947B3916CF7ULL, 0x0801F2E2858EFC16ULL,
    0x636920D871574E69ULL, 0xA458FEA3F4933D7EULL, 0x0D95748F728EB658ULL,
    0x718BCD5882154AEEULL, 0x7B54A41DC25A59B5ULL, 0x9C30D5392AF26013ULL,
    0xC5D1B023286085F0ULL, 0x1318D2B7C6B2395EULL, 0x6A5A1AE3023AD5C3ULL,
    0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL,
    0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL, 0xD69906245565A910ULL,
    0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL, 0x19A4C116B8D2D0C8ULL,
    0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL,
    0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL,
    0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL, 0x90BEFFFA23631E28ULL,
    0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL
};

/* Transform operations per level: 0=rotate, 1=xor_const, 2=multiply */
static const uint8_t deep_ops[50] = {
    0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1,
    2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0,
    1, 2, 0, 1, 2, 0, 1, 2, 0, 1
};

/* Recursive dispatcher - creates 50 levels of call depth */
static NOINLINE uint64_t deep_dispatch(uint64_t val, int level) {
    if (level >= 50) return val;

    uint64_t result;
    switch (deep_ops[level]) {
        case 0: { /* Rotate left by (level % 63 + 1) */
            uint32_t rot = (uint32_t)((level % 63) + 1);
            result = (val << rot) | (val >> (64 - rot));
            break;
        }
        case 1: /* XOR with level-specific constant */
            result = val ^ deep_constants[level];
            break;
        case 2: /* Multiply by odd constant (invertible in Z/2^64) */
            result = val * (deep_constants[level] | 1ULL);
            break;
        default:
            result = val;
            break;
    }

    /* Recursive call creates real call depth for CallGraph analysis */
    return deep_dispatch(result, level + 1);
}

NOINLINE uint64_t target_deep_callchain(uint64_t seed) {
    return deep_dispatch(seed, 0);
}

/* ---------------------------------------------------------------------------
 * D4: Decrypt-then-execute (self-modifying code pattern)
 *
 * Simulates the JIT/packed-malware pattern:
 *   1. "Encrypted bytecode" buffer (fixed ciphertext)
 *   2. Decrypt using RC4 keystream derived from seed
 *   3. Interpret decrypted bytes as VM instructions
 *
 * Tests tenet's ability to track data through decrypt -> interpret chains.
 * The decrypt phase generates unique bytecodes per seed.
 * --------------------------------------------------------------------------- */
NOINLINE uint64_t target_decrypt_execute(uint64_t seed) {
    /* RC4 key: 8 bytes from seed */
    uint8_t rc4_key[8];
    for (int i = 0; i < 8; i++) {
        rc4_key[i] = (uint8_t)(seed >> (i * 8));
    }

    /* RC4 Key Scheduling Algorithm (KSA) */
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;

    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (uint8_t)(j + S[i] + rc4_key[i % 8]);
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }

    /* "Encrypted instructions" - fixed ciphertext that decrypts differently per seed */
    static const uint8_t encrypted_code[64] = {
        0xA3, 0x5F, 0x12, 0x8B, 0xC7, 0x34, 0xE9, 0x01,
        0x67, 0xD2, 0x4A, 0xF8, 0x3E, 0x95, 0x0C, 0xB6,
        0x71, 0x28, 0xAD, 0x5C, 0xE3, 0x80, 0x49, 0xF7,
        0x1E, 0x63, 0xDA, 0x05, 0xBC, 0x92, 0x47, 0xCE,
        0x8F, 0x36, 0xA1, 0x54, 0xEB, 0x70, 0x29, 0xD8,
        0x43, 0xFE, 0x15, 0x8C, 0x67, 0xB0, 0x2E, 0x99,
        0x5A, 0xC4, 0x03, 0x7D, 0xE6, 0x41, 0xAF, 0x58,
        0xD3, 0x1C, 0x86, 0x6B, 0xF0, 0x25, 0x9E, 0x4C
    };

    /* RC4 PRGA: generate keystream and decrypt */
    uint8_t code[64];
    uint8_t ii = 0, jj = 0;
    for (int k = 0; k < 64; k++) {
        ii++;
        jj = (uint8_t)(jj + S[ii]);
        uint8_t tmp = S[ii]; S[ii] = S[jj]; S[jj] = tmp;
        uint8_t ks = S[(uint8_t)(S[ii] + S[jj])];
        code[k] = encrypted_code[k] ^ ks;
    }

    /* Interpret decrypted bytecodes (same ISA as mini_vm) */
    uint64_t vm_stack[16];
    uint64_t vm_mem[16];
    int sp = 0;
    memset(vm_stack, 0, sizeof(vm_stack));

    /* Initialize VM memory from seed */
    uint64_t gen = seed;
    for (int i = 0; i < 16; i++) {
        gen ^= gen << 13;
        gen ^= gen >> 7;
        gen ^= gen << 17;
        vm_mem[i] = gen;
    }

    /* Execute 64 decrypted instructions */
    for (int pc = 0; pc < 64; pc++) {
        uint8_t insn = code[pc];
        uint8_t opcode = insn & 0x07;
        uint8_t imm = (insn >> 3) & 0x1F;

        switch (opcode) {
            case 0: /* PUSH immediate */
                if (sp < 16) vm_stack[sp++] = (uint64_t)imm;
                break;
            case 1: /* ADD */
                if (sp >= 2) { sp--; vm_stack[sp-1] += vm_stack[sp]; }
                break;
            case 2: /* XOR */
                if (sp >= 2) { sp--; vm_stack[sp-1] ^= vm_stack[sp]; }
                break;
            case 3: /* MUL */
                if (sp >= 2) { sp--; vm_stack[sp-1] *= vm_stack[sp]; }
                break;
            case 4: /* ROT left by 13 */
                if (sp >= 1) {
                    uint64_t v = vm_stack[sp-1];
                    vm_stack[sp-1] = (v << 13) | (v >> 51);
                }
                break;
            case 5: /* DUP */
                if (sp >= 1 && sp < 16) { vm_stack[sp] = vm_stack[sp-1]; sp++; }
                break;
            case 6: /* SWAP */
                if (sp >= 2) {
                    uint64_t tmp = vm_stack[sp-1];
                    vm_stack[sp-1] = vm_stack[sp-2];
                    vm_stack[sp-2] = tmp;
                }
                break;
            case 7: /* LOAD from memory */
                if (sp >= 1) {
                    vm_stack[sp-1] = vm_mem[vm_stack[sp-1] & 0xF];
                }
                break;
        }
    }

    return (sp > 0) ? vm_stack[sp-1] : 0;
}

/* ===========================================================================
 * Sentinel: marks the end of all advanced target functions.
 * Used by the benchmark harness for address range computation.
 * =========================================================================== */
void advanced_targets_end(void) {}

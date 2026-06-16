/*
 * obfuscation_targets.c — Group B: OLLVM-equivalent obfuscation applied to XTEA
 *
 * All five variants implement XTEA-64 rounds with key={0xDEADBEEF, 0xCAFEBABE,
 * 0x12345678, 0x9ABCDEF0} and produce IDENTICAL output to the standard algorithm.
 *
 * Each function simulates a specific OLLVM pass:
 *   B1: -fla   (Control Flow Flattening)
 *   B2: -bcf   (Bogus Control Flow)
 *   B3: -sub   (Instruction Substitution / MBA)
 *   B4: -strcry (String/Constant Encryption)
 *   B5: All combined
 */

#include "advanced_targets.h"
#include <string.h>

#define NOINLINE __attribute__((noinline))

/* ═══════════════════════════════════════════════════════════════════════════════
 * B1: Control Flow Flattening (simulates OLLVM -fla pass)
 *
 * The loop is replaced by a while(1)+switch(state) dispatcher.
 * Each "basic block" performs one XTEA round, then updates the state
 * variable to select the next block. State transitions use a simple
 * hash of the round number to make the mapping non-trivial.
 *
 * Structure:
 *   state=0 → prologue (init variables)
 *   state=hash(i) for i=0..63 → round i
 *   state=EPILOGUE → return result
 * ═══════════════════════════════════════════════════════════════════════════════ */

/* Hash function for state transitions: maps round number to a state value */
static inline uint32_t cff_state_hash(uint32_t round_num) {
    uint32_t h = round_num * 0x45D9F3B;
    h = ((h >> 16) ^ h) * 0x45D9F3B;
    h = ((h >> 16) ^ h);
    return (h & 0xFFFF) + 1; /* Avoid 0 (prologue) and 0xFFFF0000 (epilogue) */
}

#define CFF_STATE_PROLOGUE  0u
#define CFF_STATE_EPILOGUE  0xFFFF0000u

NOINLINE uint64_t target_xtea_cff(uint64_t seed) {
    uint32_t v0, v1;
    uint32_t key[4] = {0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0};
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9;
    int round_idx = 0;
    uint32_t state = CFF_STATE_PROLOGUE;

    /* Pre-compute state table for all 64 rounds */
    uint32_t state_table[64];
    for (int i = 0; i < 64; i++) {
        state_table[i] = cff_state_hash((uint32_t)i);
    }

    v0 = (uint32_t)(seed & 0xFFFFFFFF);
    v1 = (uint32_t)(seed >> 32);

    /* CFF dispatcher: while(1) + switch(state) */
    while (1) {
        if (state == CFF_STATE_PROLOGUE) {
            /* Prologue state: setup complete, transition to round 0 */
            state = state_table[0];
        } else if (state == CFF_STATE_EPILOGUE) {
            /* Epilogue state: exit the dispatcher */
            break;
        } else {
            /* Find which round this state corresponds to */
            int found = -1;
            for (int i = 0; i < 64; i++) {
                if (state_table[i] == state) {
                    found = i;
                    break;
                }
            }

            if (found >= 0) {
                /* Execute one XTEA round */
                v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
                sum += delta;
                v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);

                round_idx = found + 1;

                /* Transition to next state */
                if (round_idx >= 64) {
                    state = CFF_STATE_EPILOGUE;
                } else {
                    state = state_table[round_idx];
                }
            } else {
                /* Unknown state — safety exit */
                state = CFF_STATE_EPILOGUE;
            }
        }
    }

    (void)round_idx;
    return ((uint64_t)v1 << 32) | (uint64_t)v0;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * B2: Bogus Control Flow (simulates OLLVM -bcf pass)
 *
 * Opaque predicates are inserted before/after groups of 4 rounds.
 * These predicates are mathematically always-false, so the dead branches
 * never execute, but they look like real computation to static analysis.
 *
 * Opaque predicates used:
 *   - (x*x + x) % 2 != 0        → always false (x²+x is always even)
 *   - (x*x) % 4 > 1             → always false (squares mod 4 ∈ {0,1})
 *   - ((x ^ (x>>1)) & 1) == 2   → always false (bit & 1 is 0 or 1, never 2)
 *
 * Dead branches contain plausible-looking but meaningless computation.
 * ═══════════════════════════════════════════════════════════════════════════════ */

/* Volatile sink to prevent dead code elimination */
static volatile uint32_t bcf_sink = 0;

static void bcf_dead_code_a(uint32_t *pv0, uint32_t *pv1, uint32_t s) {
    /* Looks like a modified XTEA round but with wrong constants */
    *pv0 ^= ((*pv1 << 3) ^ (*pv1 >> 7)) + *pv1 + s;
    *pv1 ^= ((*pv0 << 6) ^ (*pv0 >> 2)) + *pv0 + s;
    bcf_sink = *pv0 ^ *pv1;
}

static void bcf_dead_code_b(uint32_t *pv0, uint32_t *pv1, uint32_t s) {
    /* Another fake computation path */
    *pv0 = (*pv0 * 0x5DEECE66Du) + 0xBu;
    *pv1 = (*pv1 * 0x12345u) ^ s;
    bcf_sink = *pv0 + *pv1;
}

NOINLINE uint64_t target_xtea_bcf(uint64_t seed) {
    uint32_t v0 = (uint32_t)(seed & 0xFFFFFFFF);
    uint32_t v1 = (uint32_t)(seed >> 32);
    uint32_t key[4] = {0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0};
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9;

    /* 64 rounds, grouped in blocks of 4, with opaque predicates between groups */
    for (int group = 0; group < 16; group++) {
        /* Opaque predicate 1: (v0*v0 + v0) % 2 != 0 → ALWAYS FALSE
         * Proof: v0² + v0 = v0(v0+1), product of consecutive integers is always even */
        if (((uint64_t)v0 * (uint64_t)v0 + (uint64_t)v0) % 2 != 0) {
            /* Dead code: never reached */
            bcf_dead_code_a(&v0, &v1, sum);
            v0 ^= 0xBADC0FFEu;
            v1 ^= 0xDEADFACEu;
        }

        /* Real round 0 of this group */
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);

        /* Real round 1 of this group */
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);

        /* Opaque predicate 2: (v1*v1) % 4 > 1 → ALWAYS FALSE
         * Proof: x² mod 4 ∈ {0,1} for all x (squares are ≡ 0 or 1 mod 4)
         * Works with modular arithmetic: only low 2 bits of v1 matter */
        if (((uint32_t)(v1 * v1)) % 4 > 1) {
            /* Dead code: never reached */
            bcf_dead_code_b(&v0, &v1, sum);
            sum ^= 0xFEEDFACEu;
        }

        /* Real round 2 of this group */
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);

        /* Real round 3 of this group */
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);

        /* Opaque predicate 3: ((v0 ^ (v0 >> 1)) & 1) == 2 → ALWAYS FALSE
         * A single bit AND 1 can only be 0 or 1, never 2 */
        if (((v0 ^ (v0 >> 1)) & 1u) == 2u) {
            /* Dead code: never reached */
            bcf_dead_code_a(&v0, &v1, sum);
            bcf_dead_code_b(&v0, &v1, sum);
        }
    }

    return ((uint64_t)v1 << 32) | (uint64_t)v0;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * B3: Instruction Substitution / MBA (simulates OLLVM -sub pass)
 *
 * All arithmetic operations in the XTEA core are replaced with
 * Mixed Boolean-Arithmetic (MBA) equivalents:
 *
 *   a + b  →  (a ^ b) + 2*(a & b)  =  (a ^ b) + ((a & b) << 1)
 *   a ^ b  →  (a | b) - (a & b)
 *          or: (~a & b) | (a & ~b)
 *
 *   Shifts are kept as-is (no simpler MBA form).
 *
 * Nested substitutions are applied to increase complexity.
 * ═══════════════════════════════════════════════════════════════════════════════ */

/* MBA helper: a + b = (a ^ b) + ((a & b) << 1) */
static inline uint32_t mba_add(uint32_t a, uint32_t b) {
    return (a ^ b) + ((a & b) << 1);
}

/* MBA helper: a ^ b = (a | b) - (a & b) */
static inline uint32_t mba_xor(uint32_t a, uint32_t b) {
    return (a | b) - (a & b);
}

/* MBA helper: nested add — inner XOR also replaced */
/* a + b = ((a|b) - (a&b)) + ((a&b) << 1) */
static inline uint32_t mba_add_nested(uint32_t a, uint32_t b) {
    uint32_t a_and_b = a & b;
    uint32_t a_or_b = a | b;
    uint32_t a_xor_b = a_or_b - a_and_b;  /* MBA for a^b */
    return a_xor_b + (a_and_b << 1);       /* complete addition */
}

/* MBA helper: nested xor — bit-select form */
/* a ^ b = (~a & b) | (a & ~b) */
static inline uint32_t mba_xor_nested(uint32_t a, uint32_t b) {
    return (~a & b) | (a & ~b);
}

NOINLINE uint64_t target_xtea_sub(uint64_t seed) {
    uint32_t v0 = (uint32_t)(seed & 0xFFFFFFFF);
    uint32_t v1 = (uint32_t)(seed >> 32);
    uint32_t key[4] = {0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0};
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9;

    for (int i = 0; i < 64; i++) {
        /*
         * Original:
         *   v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
         *
         * MBA substitution applied to every operator:
         */
        {
            uint32_t shift_left = v1 << 4;
            uint32_t shift_right = v1 >> 5;
            /* (v1<<4) ^ (v1>>5) via MBA */
            uint32_t xor_shifts = mba_xor(shift_left, shift_right);
            /* ((v1<<4)^(v1>>5)) + v1 via nested MBA */
            uint32_t left_half = mba_add_nested(xor_shifts, v1);
            /* sum + key[sum & 3] via MBA */
            uint32_t right_half = mba_add(sum, key[sum & 3]);
            /* left ^ right via nested MBA (bit-select form) */
            uint32_t round_val = mba_xor_nested(left_half, right_half);
            /* v0 += round_val via nested MBA */
            v0 = mba_add_nested(v0, round_val);
        }

        /* sum += delta via MBA */
        sum = mba_add(sum, delta);

        /*
         * Original:
         *   v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
         *
         * Same MBA substitution pattern:
         */
        {
            uint32_t shift_left = v0 << 4;
            uint32_t shift_right = v0 >> 5;
            /* (v0<<4) ^ (v0>>5) via MBA */
            uint32_t xor_shifts = mba_xor(shift_left, shift_right);
            /* ((v0<<4)^(v0>>5)) + v0 via nested MBA */
            uint32_t left_half = mba_add_nested(xor_shifts, v0);
            /* sum + key[(sum>>11) & 3] via MBA */
            uint32_t right_half = mba_add(sum, key[(sum >> 11) & 3]);
            /* left ^ right via nested MBA (bit-select form) */
            uint32_t round_val = mba_xor_nested(left_half, right_half);
            /* v1 += round_val via nested MBA */
            v1 = mba_add_nested(v1, round_val);
        }
    }

    return ((uint64_t)v1 << 32) | (uint64_t)v0;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * B4: Constant Encryption (simulates OLLVM -strcry / constant encryption pass)
 *
 * All compile-time constants (key values, delta) are stored XOR-encrypted.
 * At runtime, they are decrypted into local variables before use.
 * Volatile temporaries prevent the compiler from constant-folding the decrypt.
 *
 * Encryption scheme:
 *   stored_value = real_value ^ mask
 *   runtime: real_value = stored_value ^ mask
 *
 * Masks:
 *   Key mask:   0xA5A5A5A5
 *   Delta mask: 0x3C3C3C3C
 * ═══════════════════════════════════════════════════════════════════════════════ */

#define CONSTENC_KEY_MASK   0xA5A5A5A5u
#define CONSTENC_DELTA_MASK 0x3C3C3C3Cu

/* Encrypted key values: real_key[i] ^ KEY_MASK
 *   0xDEADBEEF ^ 0xA5A5A5A5 = 0x7B081B4A
 *   0xCAFEBABE ^ 0xA5A5A5A5 = 0x6F5B1F1B
 *   0x12345678 ^ 0xA5A5A5A5 = 0xB791F3DD
 *   0x9ABCDEF0 ^ 0xA5A5A5A5 = 0x3F197B55
 */
static const uint32_t encrypted_key[4] = {
    0x7B081B4Au,
    0x6F5B1F1Bu,
    0xB791F3DDu,
    0x3F197B55u
};

/* Encrypted delta: 0x9E3779B9 ^ 0x3C3C3C3C = 0xA20B4585 */
static const uint32_t encrypted_delta = 0xA20B4585u;

NOINLINE uint64_t target_xtea_constenc(uint64_t seed) {
    uint32_t v0 = (uint32_t)(seed & 0xFFFFFFFF);
    uint32_t v1 = (uint32_t)(seed >> 32);
    uint32_t sum = 0;

    /* Runtime decryption of constants using volatile to prevent optimization */
    volatile uint32_t key_mask = CONSTENC_KEY_MASK;
    volatile uint32_t delta_mask = CONSTENC_DELTA_MASK;

    /* Decrypt key at runtime */
    uint32_t key[4];
    key[0] = encrypted_key[0] ^ key_mask;
    key[1] = encrypted_key[1] ^ key_mask;
    key[2] = encrypted_key[2] ^ key_mask;
    key[3] = encrypted_key[3] ^ key_mask;

    /* Decrypt delta at runtime */
    uint32_t delta = encrypted_delta ^ delta_mask;

    /* Standard XTEA with runtime-decrypted constants */
    for (int i = 0; i < 64; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }

    return ((uint64_t)v1 << 32) | (uint64_t)v0;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * B5: All Obfuscation Combined (fla + bcf + sub + constenc)
 *
 * This is the "maximum obfuscation" variant combining all four techniques:
 *   - CFF dispatcher (while/switch state machine)
 *   - MBA-substituted arithmetic in each round
 *   - Opaque predicates guarding state transitions
 *   - Constants encrypted and decrypted in the prologue state
 *
 * This simulates a binary protected with all OLLVM passes enabled simultaneously.
 * ═══════════════════════════════════════════════════════════════════════════════ */

/* State hash for the combined variant (different constants from B1) */
static inline uint32_t allobf_state_hash(uint32_t round_num) {
    uint32_t h = round_num ^ 0xBAADF00Du;
    h = h * 2654435761u;  /* Knuth multiplicative hash */
    h = ((h >> 13) ^ h) * 1274126177u;
    h = (h >> 16) ^ h;
    return (h & 0x3FFFu) + 1u; /* Range [1, 0x3FFF] */
}

#define ALLOBF_STATE_PROLOGUE  0u
#define ALLOBF_STATE_EPILOGUE  0xFFFE0000u

/* Encrypted constants for combined variant (different masks for variety) */
#define ALLOBF_KEY_MASK   0x5A5A5A5Au
#define ALLOBF_DELTA_MASK 0xC3C3C3C3u

/* Encrypted key: real ^ 0x5A5A5A5A
 *   0xDEADBEEF ^ 0x5A5A5A5A = 0x84F7E4B5
 *   0xCAFEBABE ^ 0x5A5A5A5A = 0x90A4E0E4
 *   0x12345678 ^ 0x5A5A5A5A = 0x486E0C22
 *   0x9ABCDEF0 ^ 0x5A5A5A5A = 0xC0E684AA
 */
static const uint32_t allobf_enc_key[4] = {
    0x84F7E4B5u,
    0x90A4E0E4u,
    0x486E0C22u,
    0xC0E684AAu
};

/* Encrypted delta: 0x9E3779B9 ^ 0xC3C3C3C3 = 0x5DF4BA7A */
static const uint32_t allobf_enc_delta = 0x5DF4BA7Au;

NOINLINE uint64_t target_xtea_allobf(uint64_t seed) {
    uint32_t v0, v1;
    uint32_t key[4];
    uint32_t sum = 0;
    uint32_t delta = 0;
    uint32_t state = ALLOBF_STATE_PROLOGUE;

    /* Pre-compute state table */
    uint32_t state_table[64];
    for (int i = 0; i < 64; i++) {
        state_table[i] = allobf_state_hash((uint32_t)i);
    }

    v0 = (uint32_t)(seed & 0xFFFFFFFF);
    v1 = (uint32_t)(seed >> 32);

    /* CFF dispatcher with all obfuscation techniques */
    while (1) {
        if (state == ALLOBF_STATE_PROLOGUE) {
            /* ═══ Prologue: Constant decryption (constenc pass) ═══ */
            volatile uint32_t km = ALLOBF_KEY_MASK;
            volatile uint32_t dm = ALLOBF_DELTA_MASK;

            key[0] = allobf_enc_key[0] ^ km;
            key[1] = allobf_enc_key[1] ^ km;
            key[2] = allobf_enc_key[2] ^ km;
            key[3] = allobf_enc_key[3] ^ km;
            delta = allobf_enc_delta ^ dm;

            /* Opaque predicate (bcf): (v0*v0 + v0) % 2 != 0 → always false */
            if (((uint64_t)v0 * (uint64_t)v0 + (uint64_t)v0) % 2 != 0) {
                /* Dead code */
                key[0] ^= 0xFFFFFFFFu;
                key[1] ^= 0xFFFFFFFFu;
            }

            /* Transition to first round */
            state = state_table[0];

        } else if (state == ALLOBF_STATE_EPILOGUE) {
            /* ═══ Epilogue: exit dispatcher ═══ */
            break;

        } else {
            /* ═══ Round states: find and execute ═══ */
            int found = -1;
            for (int i = 0; i < 64; i++) {
                if (state_table[i] == state) {
                    found = i;
                    break;
                }
            }

            if (found >= 0) {
                /* Opaque predicate before round (bcf):
                 * (v1*v1) % 4 > 1 → always false (squares mod 4 ∈ {0,1}) */
                if (((uint32_t)(v1 * v1)) % 4 > 1) {
                    /* Dead code */
                    v0 ^= 0xDEADC0DEu;
                    v1 ^= 0xCAFEF00Du;
                    sum = 0;
                }

                /* ═══ XTEA half-round 1 with MBA (sub pass) ═══ */
                /* v0 += (((v1<<4) ^ (v1>>5)) + v1) ^ (sum + key[sum&3]) */
                {
                    uint32_t sl = v1 << 4;
                    uint32_t sr = v1 >> 5;
                    /* sl ^ sr via MBA: (sl | sr) - (sl & sr) */
                    uint32_t xor_part = (sl | sr) - (sl & sr);
                    /* xor_part + v1 via MBA: (a^b) + ((a&b)<<1) */
                    uint32_t left = (xor_part ^ v1) + ((xor_part & v1) << 1);
                    /* sum + key[sum&3] via MBA */
                    uint32_t ki = key[sum & 3];
                    uint32_t right = (sum ^ ki) + ((sum & ki) << 1);
                    /* left ^ right via MBA: (~a & b) | (a & ~b) */
                    uint32_t round_val = (~left & right) | (left & ~right);
                    /* v0 += round_val via MBA */
                    v0 = (v0 ^ round_val) + ((v0 & round_val) << 1);
                }

                /* sum += delta via MBA */
                sum = (sum ^ delta) + ((sum & delta) << 1);

                /* ═══ XTEA half-round 2 with MBA (sub pass) ═══ */
                /* v1 += (((v0<<4) ^ (v0>>5)) + v0) ^ (sum + key[(sum>>11)&3]) */
                {
                    uint32_t sl = v0 << 4;
                    uint32_t sr = v0 >> 5;
                    /* sl ^ sr via MBA */
                    uint32_t xor_part = (sl | sr) - (sl & sr);
                    /* xor_part + v0 via MBA */
                    uint32_t left = (xor_part ^ v0) + ((xor_part & v0) << 1);
                    /* sum + key[(sum>>11)&3] via MBA */
                    uint32_t ki = key[(sum >> 11) & 3];
                    uint32_t right = (sum ^ ki) + ((sum & ki) << 1);
                    /* left ^ right via MBA */
                    uint32_t round_val = (~left & right) | (left & ~right);
                    /* v1 += round_val via MBA */
                    v1 = (v1 ^ round_val) + ((v1 & round_val) << 1);
                }

                /* Opaque predicate after round (bcf):
                 * ((v0 ^ (v0>>1)) & 1) == 2 → always false */
                if (((v0 ^ (v0 >> 1)) & 1u) == 2u) {
                    /* Dead code */
                    v0 = ~v0;
                    v1 = ~v1;
                }

                /* State transition (CFF) */
                if (found + 1 >= 64) {
                    state = ALLOBF_STATE_EPILOGUE;
                } else {
                    state = state_table[found + 1];
                }
            } else {
                /* Unknown state — safety exit */
                state = ALLOBF_STATE_EPILOGUE;
            }
        }
    }

    return ((uint64_t)v1 << 32) | (uint64_t)v0;
}

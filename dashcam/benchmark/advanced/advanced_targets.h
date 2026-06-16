/*
 * qbditrace advanced benchmark — target function declarations
 *
 * These targets go beyond simple algorithm testing. They implement:
 *   1. Full production-grade crypto algorithms (with real S-Boxes/constants)
 *   2. Manually-applied obfuscation techniques equivalent to OLLVM passes
 *   3. Combined crypto+obfuscation scenarios (typical of protected iOS apps)
 *
 * Each target returns a deterministic uint64_t checksum so correctness can
 * be verified even through obfuscation layers.
 *
 * Designed to exercise tenet's analysis capabilities:
 *   - PatternPass: detect AES S-Box, SHA256 constants, ChaCha quarter-round
 *   - CFGPass: rebuild control flow from CFF-flattened traces
 *   - TaintPass: track key material through crypto operations
 *   - XRefPass: identify cross-references between crypto stages
 *   - SlicePass: extract key-dependent computation slices
 */

#ifndef QBDITRACE_ADVANCED_TARGETS_H
#define QBDITRACE_ADVANCED_TARGETS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Group A: Production Crypto Algorithms (unobfuscated baseline)
 *
 * These implement full, correct algorithms. Tenet should be able to:
 *   - Detect known constants via PatternPass
 *   - Trace key→ciphertext data flow via TaintPass
 *   - Identify round structure via CFGPass
 * ═══════════════════════════════════════════════════════════════════════════ */

/* AES-128 ECB: full 10-round encryption with real S-Box + MixColumns.
 * seed[0:15] = plaintext, hardcoded key.
 * Returns: checksum of 16-byte ciphertext. */
uint64_t target_aes128_encrypt(uint64_t seed);

/* AES-128 key expansion only. Isolates key schedule for taint analysis.
 * seed = first 8 bytes of key; returns checksum of expanded round keys. */
uint64_t target_aes128_keyexp(uint64_t seed);

/* ChaCha20 quarter-round × 20 (full block).
 * seed = nonce input; returns checksum of 64-byte keystream block. */
uint64_t target_chacha20_block(uint64_t seed);

/* SHA-256 compression function (single 64-byte block).
 * seed fills the message block; returns low 64 bits of hash. */
uint64_t target_sha256_compress(uint64_t seed);

/* HMAC-SHA256(key, msg) where key and msg are derived from seed.
 * Tests nested hash + key padding. Returns low 64 bits. */
uint64_t target_hmac_sha256(uint64_t seed);

/* XTEA: 64 rounds (double standard). Stronger than TEA.
 * seed = plaintext; returns ciphertext as uint64. */
uint64_t target_xtea64(uint64_t seed);

/* SM4 (Chinese national standard block cipher): full 32-round encryption.
 * seed = plaintext, hardcoded key. Returns checksum. */
uint64_t target_sm4_encrypt(uint64_t seed);

/* ═══════════════════════════════════════════════════════════════════════════
 * Group B: OLLVM-equivalent Obfuscation (applied to XTEA core)
 *
 * Each variant applies a SINGLE OLLVM pass to the same algorithm (XTEA),
 * allowing direct comparison of tenet's ability to see through each technique.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* B1: Control Flow Flattening (fla)
 * XTEA wrapped in a while(1)+switch state machine. 
 * Tenet CFGPass should recover 64 sequential rounds. */
uint64_t target_xtea_cff(uint64_t seed);

/* B2: Bogus Control Flow (bcf)
 * XTEA with injected dead-code branches guarded by opaque predicates.
 * Tenet should identify unreachable paths via dynamic analysis. */
uint64_t target_xtea_bcf(uint64_t seed);

/* B3: Instruction Substitution (sub)
 * XTEA with all ADD/XOR/SHIFT replaced by equivalent MBA expressions.
 * E.g., a+b → (a^b) + 2*(a&b), a^b → (a|b) - (a&b)
 * Tenet TaintPass should still track data flow correctly. */
uint64_t target_xtea_sub(uint64_t seed);

/* B4: String/Constant Encryption (strcry-like)
 * XTEA key and delta constant are XOR-encrypted at rest, decrypted at runtime.
 * Tenet should detect the decrypt-then-use pattern. */
uint64_t target_xtea_constenc(uint64_t seed);

/* B5: All passes combined (fla + bcf + sub + constenc)
 * Maximum obfuscation: the most realistic scenario.
 * Tenet must handle all techniques simultaneously. */
uint64_t target_xtea_allobf(uint64_t seed);

/* ═══════════════════════════════════════════════════════════════════════════
 * Group C: Real-World Scenarios (combined crypto + protection patterns)
 *
 * These simulate patterns found in actual protected iOS/Android apps:
 *   - Anti-tamper integrity checks
 *   - Key derivation chains
 *   - Request signing pipelines
 *   - VM-dispatcher-like bytecode engines
 * ═══════════════════════════════════════════════════════════════════════════ */

/* C1: PBKDF2-HMAC-SHA256 key derivation (1000 iterations).
 * Stresses tenet's ability to handle long repetitive traces.
 * Returns low 64 bits of derived key. */
uint64_t target_pbkdf2_sha256(uint64_t seed);

/* C2: Request signing pipeline:
 *     timestamp → HMAC(secret, path+timestamp+body) → hex encode
 * Simulates typical API signing seen in protected mobile apps.
 * Returns checksum of the signature. */
uint64_t target_request_sign(uint64_t seed);

/* C3: Anti-tamper self-check:
 *     CRC32 over a "code region" + compare with stored hash.
 *     If mismatch, corrupt output. Tests pattern detection. */
uint64_t target_antitamper_crc(uint64_t seed);

/* C4: Mini VM interpreter (8 opcodes, 64 bytecodes derived from seed).
 *     Simulates VMP-style code virtualization.
 *     Tests tenet's ability to reconstruct meaningful semantics. */
uint64_t target_mini_vm(uint64_t seed);

/* C5: Layered encryption: AES-128(ChaCha20(XTEA(plaintext)))
 *     Three nested encryption layers. Tests deep taint propagation.
 *     Returns checksum of final ciphertext. */
uint64_t target_layered_crypto(uint64_t seed);

/* C6: CFF-protected AES with MBA-substituted S-Box lookups.
 *     The "boss fight" — hardest target for any analysis tool.
 *     Combines Groups A+B techniques on a complex algorithm. */
uint64_t target_aes_cff_mba(uint64_t seed);

/* ═══════════════════════════════════════════════════════════════════════════
 * Group D: Tenet-specific stress tests
 *
 * Designed to push specific tenet analysis passes to their limits.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* D1: Maximum branch divergence (1024 paths from 10-bit seed selection).
 * Stress test for CFG reconstruction with many unique edges. */
uint64_t target_branch_explosion(uint64_t seed);

/* D2: Memory-intensive AES with S-Box in a large lookup table.
 * Stress test for memory model (many distinct addresses accessed). */
uint64_t target_aes_tablebased(uint64_t seed);

/* D3: Deeply nested function calls (call depth ~50).
 * CallGraph pass stress test. */
uint64_t target_deep_callchain(uint64_t seed);

/* D4: Self-modifying-like pattern: decrypt code buffer, call it.
 * Actually just decrypts data and interprets it, but the pattern
 * mimics JIT/self-mod code for tenet's analysis. */
uint64_t target_decrypt_execute(uint64_t seed);

#ifdef __cplusplus
}
#endif

/* Sentinel for range computation */
void advanced_targets_end(void);

#endif /* QBDITRACE_ADVANCED_TARGETS_H */

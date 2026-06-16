/*
 * qbditrace benchmark — target function declarations
 *
 * Each target is a pure function: uint64_t target_xxx(uint64_t seed)
 * The harness calls each one both natively and under instrumentation,
 * then compares return values to verify correctness.
 *
 * Targets are grouped by complexity category:
 *   1. Simple: basic arithmetic, linear control flow
 *   2. Branchy: many conditional branches (stress branch tracing)
 *   3. Loopy: nested loops (stress memory R/W recording)
 *   4. Recursive: deep recursion (stress call/return tracking)
 *   5. CFF-like: simulated control-flow flattening (state-machine dispatch)
 *   6. Crypto: real-world algorithms (AES S-box, TEA, MD5-round)
 *   7. Large: long execution traces (performance benchmark)
 */

#ifndef QBDITRACE_BENCHMARK_TARGETS_H
#define QBDITRACE_BENCHMARK_TARGETS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Category 1: Simple (short traces, correctness baseline) ------------- */

/* Pure arithmetic mixing (< 50 instructions) */
uint64_t target_arith_mix(uint64_t seed);

/* Bitwise operations: shifts, rotates, masks */
uint64_t target_bitops(uint64_t seed);

/* --- Category 2: Branchy (many conditional paths) ------------------------ */

/* 32-way if-else chain based on seed bits */
uint64_t target_branch32(uint64_t seed);

/* Nested conditionals: 4 levels × 4 branches = 256 paths */
uint64_t target_nested_branch(uint64_t seed);

/* --- Category 3: Loopy (memory-intensive) -------------------------------- */

/* Bubble sort on a 64-element array derived from seed */
uint64_t target_bubblesort(uint64_t seed);

/* Matrix multiply 8×8 (lots of loads/stores) */
uint64_t target_matmul8(uint64_t seed);

/* Linked list traversal (pointer chasing) */
uint64_t target_linkedlist(uint64_t seed);

/* --- Category 4: Recursive (deep call stacks) ---------------------------- */

/* Fibonacci (exponential recursion, depth ~25) */
uint64_t target_fib25(uint64_t seed);

/* Ackermann(3, n%8) — deeply nested recursion */
uint64_t target_ackermann(uint64_t seed);

/* Merge sort on 32 elements (recursive divide & conquer) */
uint64_t target_mergesort(uint64_t seed);

/* --- Category 5: CFF-like (control-flow flattening simulation) ----------- */

/* Switch-based state machine: 16 states, seed-driven transitions */
uint64_t target_cff_switch16(uint64_t seed);

/* Computed-goto dispatch (if compiler supports it, else switch fallback) */
uint64_t target_cff_dispatch(uint64_t seed);

/* Opaque predicate chains: branches that always/never taken but look random */
uint64_t target_opaque_pred(uint64_t seed);

/* --- Category 6: Crypto (real algorithm kernels) ------------------------- */

/* TEA (Tiny Encryption Algorithm) — 32 rounds */
uint64_t target_tea_encrypt(uint64_t seed);

/* RC4 key schedule + encrypt 64 bytes */
uint64_t target_rc4(uint64_t seed);

/* MD5 single-block transform */
uint64_t target_md5_block(uint64_t seed);

/* --- Category 7: Large traces (performance stress) ----------------------- */

/* 10K iterations of a hash-mixing loop */
uint64_t target_hash_10k(uint64_t seed);

/* 100K iterations (large trace file) */
uint64_t target_hash_100k(uint64_t seed);

/* Combination: sort + encrypt + hash (longest trace) */
uint64_t target_combined(uint64_t seed);

#ifdef __cplusplus
}
#endif

/* Sentinel: placed after all target code for range computation */
void benchmark_targets_end(void);

#endif /* QBDITRACE_BENCHMARK_TARGETS_H */

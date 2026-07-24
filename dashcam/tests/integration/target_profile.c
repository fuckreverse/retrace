/*
 * qbditrace - profile/memory-flavoured E2E test target
 *
 * target_profile.c
 *
 * Deliberately exercises the signal shapes tenet's profile- and
 * memory-analysis passes look for, so their pass-level e2e
 * (tools/qbditrace/tests/integration/e2e/pass_profile.sh and
 * pass_memory.sh) can run against a real recorded trace instead of a
 * hand-built fixture:
 *
 *   1. trace_fold   - a long, uniform loop (32 iterations, no data-dependent
 *                     branching inside the body) that TraceFoldPass can fold
 *                     into a summarized repeated-iteration block
 *                     (min_iterations_to_fold defaults to 3, so 32 is
 *                     comfortably over threshold and gives --trace-fold a
 *                     wide [start,end) inst_id window to pick from).
 *   2. mem_search   - a known 64-bit sentinel value written to a stack
 *                     buffer, exact-value searchable via
 *                     `--mem-search-value <hex>`.
 *   3. entropy /
 *      yara_mem_scan - a high-entropy buffer produced by an xorshift64
 *                     PRNG (approximates ciphertext/packed-payload entropy;
 *                     avoids the low-entropy, highly-repetitive patterns a
 *                     naive counter or memset would produce).
 *
 * Every other profile pass exercisable via `--reg-timeline` / `--call-context`
 * / `--window-stats` / `--dataflow-graph` / `--trace-diff` does not need
 * dedicated code shapes: they operate on arbitrary inst_id/register/address
 * ranges and are already well covered by test_target.c ("core") and
 * target_crypto.c ("crypto"). This file exists only for the two signal
 * shapes above that neither of those targets produce.
 *
 * Kept separate from test_target.c / target_crypto.c so each produced trace
 * stays small and focused (see target_crypto.c's header comment for the same
 * rationale).
 */

#include <stdint.h>

/* ---- 1. trace_fold: long uniform loop (32 iterations) -------------------- */

/*
 * `count` MUST be a genuine runtime value (see target_crypto.c's
 * arx_mix_loop() for why: -O2 fully unrolls small loops with a
 * compile-time-visible trip count, leaving no back-edge for LoopPass/
 * TraceFoldPass to fold). The volatile guard forces it through memory.
 *
 * `#pragma clang loop vectorize(disable)` is required too: without it -O2
 * auto-vectorizes the LCG step into NEON instructions that this build's QBDI
 * disassembler cannot decode, aborting the harness process entirely
 * ("Disassembly error ... fail to parse address", SIGABRT) rather than just
 * producing a wrong/unrolled trace. Scalar code only.
 */
__attribute__((noinline)) static uint64_t
uniform_accumulate_loop(uint64_t seed, int count) {
  volatile int guard = count;
  int n = guard;
  uint64_t acc = seed;
#pragma clang loop vectorize(disable) interleave(disable)
  for (int i = 0; i < n; ++i) {
    acc = acc * 1103515245u + 12345u; /* uniform LCG step: identical shape
                                        * every iteration -> ideal fold
                                        * candidate (no data-dependent
                                        * control flow inside the body) */
  }
  return acc;
}

/* ---- 2. mem_search: known sentinel value written to memory --------------- */

/* Keep in sync with the e2e assertion in e2e/pass_memory.sh
 * (--mem-search-value 0xCAFEF00DDEADC0DE). Written to a stack slot the
 * tracer's REC_MEM records will capture as a write, then read back so the
 * store cannot be optimised away as dead. */
#define PROFILE_SENTINEL_VALUE 0xCAFEF00DDEADC0DEULL

__attribute__((noinline)) static uint64_t
stash_sentinel(volatile uint64_t *slot) {
  *slot = PROFILE_SENTINEL_VALUE;
  return *slot;
}

/* ---- 3. entropy / yara_mem_scan: high-entropy buffer via xorshift64 ------ */

/* Scalar only -- see uniform_accumulate_loop()'s comment above for why the
 * vectorize(disable) pragma is required (NEON output otherwise crashes the
 * QBDI disassembler used by the harness). */
__attribute__((noinline)) static void
fill_high_entropy_buffer(uint64_t *buf, int n, uint64_t seed) {
  volatile int guard = n;
  int count = guard;
  uint64_t x = seed ? seed : 0x2545F4914F6CDD1DULL; /* xorshift64 requires a
                                                       * non-zero state */
#pragma clang loop vectorize(disable) interleave(disable)
  for (int i = 0; i < count; ++i) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    buf[i] = x;
  }
}

/*
 * XOR-reduce a buffer into a single scalar via a volatile accumulator.
 *
 * Kept in its own noinline function (not a `#pragma clang loop
 * vectorize(disable)` loop at the call site) because -O2 was still emitting
 * an `eor3` (ARMv8.2-SHA3, 3-way XOR) reduction-tree instruction for the
 * inline loop form despite the pragma -- this build's QBDI disassembler
 * cannot decode eor3 and aborts the whole harness process (SIGABRT). Routing
 * every accumulation through a volatile pointer forces a genuine
 * memory-ordered scalar loop that the vectorizer cannot restructure into a
 * reduction tree.
 */
__attribute__((noinline)) static uint64_t
xor_reduce_buffer(const uint64_t *buf, int n) {
  volatile uint64_t acc = 0;
  volatile int guard = n;
  int count = guard;
  for (int i = 0; i < count; ++i) {
    acc = acc ^ buf[i];
  }
  return acc;
}

/* ---- the single entry point the tracer takes over ------------------------ */

uint64_t profile_target(uint64_t seed) {
  uint64_t branchy = 0;

  /* 1. Long uniform loop -> trace_fold candidate. */
  uint64_t folded = uniform_accumulate_loop(seed, 32);
  branchy ^= folded;

  /* 2. Sentinel value -> mem_search exact-value hit. */
  uint64_t sentinel_slot = 0;
  uint64_t observed = stash_sentinel(&sentinel_slot);
  branchy ^= observed;

  /* 3. High-entropy buffer -> entropy / yara_mem_scan. */
  uint64_t hi_entropy[16];
  fill_high_entropy_buffer(hi_entropy, 16, seed ^ folded);
  branchy ^= xor_reduce_buffer(hi_entropy, 16);

  return branchy;
}

/*
 * Sentinel symbol immediately following profile_target in the source so the
 * harness can use its address as the (exclusive) end of the instrumented
 * range. It must do nothing interesting.
 */
void profile_target_end(void) { /* intentionally empty */ }

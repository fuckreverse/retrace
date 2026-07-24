/*
 * qbditrace - crypto-flavoured E2E test target
 *
 * target_crypto.c
 *
 * Deliberately exercises the signal shapes tenet's crypto-analysis passes
 * look for, so their pass-level e2e (tools/qbditrace/tests/integration/e2e/
 * pass_crypto.sh) can run against a real recorded trace instead of a
 * hand-built fixture:
 *
 *   1. pattern           - a movz+movk pair materializing the TEA "golden
 *                          ratio" delta constant (0x9E3779B9), which
 *                          PatternCollector::lookup_known_constant() resolves
 *                          to a named hit (KnownConstant "TEA_DELTA", algo
 *                          "TEA") — see known_db() in pattern_pass.cpp.
 *   2. loop_semantics    - two classifiable loops:
 *                            a) an XOR-mixing loop (ARX-adjacent: xor + add +
 *                               ror) over several iterations
 *                            b) a pure XOR "stream cipher" style loop over a
 *                               buffer (has_xor_mix, no add/shift -> XOR_MIX)
 *   3. algorithm_summary - cross-references the pattern + loop signals above
 *                          into an algorithm identification.
 *   4. objc_crypto       - an ObjC message send ([KeyStore secretKey]-style
 *                          getter) whose return value feeds the crypto
 *                          constant/loop below, so ObjcCryptoPass can
 *                          correlate the two.
 *
 * Kept separate from test_target.c (the "core" scenario) so each produced
 * trace stays small and focused: adding these extra instructions to the core
 * target would blow past compute_range()'s conservative span assumptions and
 * dilute the core scenario's pass/mem/objc/svc assertions with unrelated
 * crypto noise.
 *
 * NOTE: keep helpers noinline (mirrors test_target.c) so cross-function calls
 * are still emitted for passes that rely on them.
 */

#include <stdint.h>

#if defined(QBDITRACE_TEST_OBJC)
#include <objc/message.h>
#include <objc/runtime.h>
#endif

/* ---- 1. pattern: TEA golden-ratio delta constant materialization -------- */

__attribute__((noinline)) static uint64_t
materialize_tea_delta_constant(void) {
  /* movz w0, #0x79b9 ; movk w0, #0x9e37, lsl #16  =>  w0 = 0x9E3779B9
   * (exact match for KnownConstant "TEA_DELTA" registered in
   * PatternCollector::known_db(), pattern_pass.cpp). Volatile round-trip
   * through a local to discourage the optimiser from folding the two
   * immediates into one `mov w0, #0x9e3779b9` (which would still form a
   * movz+movk pair at -O0/-O1 but is not guaranteed at -O2; the volatile
   * forces materialization at the call site regardless of optimisation
   * level). */
  volatile uint32_t v = 0x79b9;
  v |= (uint32_t)0x9e37 << 16;
  return (uint64_t)v;
}

/* ---- 2a. loop_semantics: ARX-ish mixing loop (xor + add + rotate) -------- */

/*
 * `rounds` MUST be a genuine runtime value (not a compile-time constant
 * visible to the caller) or -O2 will fully unroll this small loop, leaving
 * no back-edge in the trace for CFGPass/LoopPass to detect (verified: with a
 * literal iteration count every PC in the trace appears exactly once). The
 * `volatile` read forces the count through memory so the compiler cannot
 * constant-propagate it from the call site.
 */
__attribute__((noinline)) static uint64_t
arx_mix_loop(uint64_t state, uint64_t key, int rounds) {
  volatile int guard = rounds;
  int n = guard;
#pragma clang loop vectorize(disable) interleave(disable)
  for (int i = 0; i < n; ++i) {
    state ^= key;                                   /* xor */
    state = state + (uint64_t)(i * 0x9E3779B9u);     /* add (addition chain) */
    state = (state << 13) | (state >> (64 - 13));    /* rotate */
    key = key + 1;
  }
  return state;
}

/* ---- 2b. loop_semantics: pure XOR stream-cipher style loop --------------- */

/* Same anti-unroll guard as arx_mix_loop() above. */
__attribute__((noinline)) static uint64_t
xor_stream_loop(uint64_t *buf, int n, uint64_t key) {
  volatile int guard = n;
  int count = guard;
  uint64_t acc = 0;
#pragma clang loop vectorize(disable) interleave(disable)
  for (int i = 0; i < count; ++i) {
    buf[i] ^= key;   /* xor mix, no shift/add -> classified as XOR_MIX */
    acc ^= buf[i];
    key = (key << 1) ^ (key >> 63); /* keystream advance (kept as xor/shift
                                      * on `key`, not on buf[i], so the loop
                                      * body's dominant signal stays XOR) */
  }
  return acc;
}

/* ---- the single entry point the tracer takes over ------------------------ */

uint64_t crypto_target(uint64_t seed) {
  uint64_t branchy = 0;

#if defined(QBDITRACE_TEST_OBJC)
  /* 4. objc_crypto: an ObjC getter ([KeyStore secretKey]-shaped) whose return
   *    value flows directly into the crypto mixing below, so ObjcCryptoPass
   *    can correlate the pattern/loop hit with the preceding ObjC call. */
  uint64_t objc_key = seed;
  Class cls = objc_getClass("NSObject");
  if (cls) {
    SEL selDesc = sel_registerName("description");
    id desc = ((id (*)(id, SEL))objc_msgSend)((id)cls, selDesc);
    if (desc) {
      objc_key ^= (uint64_t)(uintptr_t)desc;
    }
  }
#else
  uint64_t objc_key = seed;
#endif

  /* 1. TEA delta constant materialization. */
  uint64_t tea_delta = materialize_tea_delta_constant();
  branchy ^= tea_delta;

  /* 2a. ARX mixing loop, seeded from the (possibly ObjC-derived) key.
   * 16 rounds: enough that even if some future toolchain partially unrolls
   * (e.g. by 2x/4x), a detectable back-edge still remains. */
  uint64_t mixed = arx_mix_loop(seed ^ tea_delta, objc_key, 16);
  branchy ^= mixed;

  /* 2b. XOR stream loop over a small buffer. */
  uint64_t buf[16];
  for (int i = 0; i < 16; ++i) {
    buf[i] = seed + (uint64_t)i;
  }
  uint64_t xored = xor_stream_loop(buf, 16, mixed);
  branchy ^= xored;

  return branchy;
}

/*
 * Sentinel symbol immediately following crypto_target in the source so the
 * harness can use its address as the (exclusive) end of the instrumented
 * range. It must do nothing interesting.
 */
void crypto_target_end(void) { /* intentionally empty */ }

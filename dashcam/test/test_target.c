/*
 * qbditrace - self-contained test target
 *
 * test_target.c
 *
 * A deliberately simple target that exercises the five trace features we want
 * to validate on Apple Silicon (macOS arm64) before going to a real iOS device:
 *
 *   1. control flow      - branches, a loop and recursion (BB sequence,
 *                           register before/after values)
 *   2. memory read/write  - load/store over a local array (mem R/W records)
 *   3. cross-function call - calls into a non-inlined helper (EXEC_TRANSFER_CALL
 *                            / RETURN with site -> target)
 *   4. objc_msgSend       - an Objective-C message send (OBJC record); compiled
 *                            in only when QBDITRACE_TEST_OBJC is defined
 *   5. svc / syscall      - getpid() bottoms out in an `svc #0x80` (SVC record)
 *
 * Everything the tracer should observe lives inside trace_target(). The symbol
 * trace_target_end() is placed right after it so the harness can derive a safe
 * upper bound for the instrumented range without parsing Mach-O.
 *
 * NOTE: keep these functions free of aggressive inlining so the cross-function
 * call is actually emitted. We mark the helper noinline and compile the file at
 * a modest optimisation level from the build command.
 */

#include <stdint.h>
#include <unistd.h>

#if defined(QBDITRACE_TEST_OBJC)
#include <objc/message.h>
#include <objc/runtime.h>
#endif

/* ---- 3. cross-function call target -------------------------------------- */

__attribute__((noinline)) static uint64_t helper_sum(const uint64_t *p,
                                                     int n) {
  uint64_t acc = 0;
  for (int i = 0; i < n; ++i) {
    acc += p[i]; /* memory read */
  }
  return acc;
}

/* ---- 1. recursion (control flow) ---------------------------------------- */

__attribute__((noinline)) static uint64_t fib(uint64_t n) {
  if (n < 2) {
    return n;
  }
  return fib(n - 1) + fib(n - 2);
}

/* ---- the single entry point the tracer takes over ----------------------- */

/*
 * Returns a checksum mixing all the sub-results so the optimiser cannot drop
 * any of the work. The harness compares this against a reference computed
 * outside the VM to confirm semantic correctness under instrumentation.
 */
uint64_t trace_target(uint64_t seed) {
  /* 2. memory write: fill a local array */
  uint64_t buf[8];
  for (int i = 0; i < 8; ++i) {
    buf[i] = seed + (uint64_t)i * 3u; /* store */
  }

  /* 1. control flow: branch on parity */
  uint64_t branchy = 0;
  if ((seed & 1u) == 0) {
    branchy = seed * 2u;
  } else {
    branchy = seed + 7u;
  }

  /* 3. cross-function call + 2. memory read inside helper */
  uint64_t s = helper_sum(buf, 8);

  /* 1. recursion */
  uint64_t f = fib(10);

  /* 5a. syscall via libc: getpid() bottoms out in an `svc #0x80` -- but that
   *     svc lives inside libsystem (the dyld shared cache), i.e. OUTSIDE the
   *     instrumented range, so it surfaces only as an EXEC_TRANSFER_CALL, not
   *     as an SVC record. This mirrors normal library calls on iOS. */
  uint64_t pid = (uint64_t)getpid();

  /* 5b. inline syscall: emit `svc #0x80` ourselves so the trap instruction is
   *     INSIDE the instrumented range. This is exactly the pattern obfuscated /
   *     anti-debug iOS code uses to bypass libc, and it is what our SVC hook is
   *     meant to catch. Darwin arm64 convention: selector in x16, args x0..x5.
   *     We call getpid (syscall #20) directly. */
  uint64_t inline_pid = 0;
#if defined(__aarch64__) || defined(__arm64__)
  {
    register uint64_t x16 __asm__("x16") = 20; /* SYS_getpid */
    register uint64_t x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0x80" : "=r"(x0) : "r"(x16) : "cc", "memory");
    inline_pid = x0;
  }
#endif

#if defined(QBDITRACE_TEST_OBJC)
  /* 4. objc_msgSend: [NSObject description] */
  Class cls = objc_getClass("NSObject");
  if (cls) {
    SEL selDesc = sel_registerName("description");
    id desc = ((id (*)(id, SEL))objc_msgSend)((id)cls, selDesc);
    if (desc) {
      branchy ^= (uint64_t)(uintptr_t)desc;
    }
  }
#endif

  return branchy ^ s ^ (f << 1) ^ (pid << 8) ^ (inline_pid << 16);
}

/*
 * Sentinel symbol immediately following trace_target in the source so the
 * harness can use its address as the (exclusive) end of the instrumented
 * range. It must do nothing interesting.
 */
void trace_target_end(void) { /* intentionally empty */ }

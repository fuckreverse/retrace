/*
 * mt_target.c — Android multi-thread qbditrace e2e target (Frida-driven).
 *
 * Unlike dashcam/tests/integration/test_harness.c (which dlopen's
 * libqbditrace.so and drives configure/run_call itself), this target does
 * NOT call any qbditrace API. It is driven entirely by the Frida agent
 * (qbditrace.js) via --trace-threads: the agent installs a pthread_create
 * interceptor so that child threads created inside mt_driver() are
 * redirected into qbditrace_run_thread() and recorded into the same trace.
 *
 * Layout:
 *   worker()          — child-thread body: memory R/W + loop + inline SVC
 *   worker_thread()    — pthread start_routine wrapper around worker()
 *   mt_driver(seed)    — Frida HOOK entry: creates 2 child threads, joins
 *   mt_driver_end()   — sentinel for instrumented range upper bound
 *   main()            — calls mt_driver(0x1234) once so a Frida HOOK on
 *                       mt_driver fires; returns low byte as exit code.
 *
 * Inline SVC uses the Linux aarch64 ABI (x8 = syscall number, svc #0),
 * NOT Darwin's (x16 selector, svc #0x80). __NR_getpid == 172 on aarch64.
 */
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

/* child-thread work: array fill (mem W) + sum (mem R) + inline SVC getpid */
__attribute__((noinline)) uint64_t worker(uint64_t seed) {
    uint64_t buf[8];
    for (int i = 0; i < 8; ++i) buf[i] = seed + (uint64_t)i * 3u;   /* mem W */
    uint64_t s = 0;
    for (int i = 0; i < 8; ++i) s += buf[i];                         /* mem R */
    /* inline SVC getpid — Linux aarch64: x8=172, svc #0 */
    uint64_t pid = 0;
    register uint64_t x8 __asm__("x8") = 172;
    register uint64_t x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "cc", "memory");
    pid = x0;
    return s ^ (pid << 8) ^ seed;
}

static void *worker_thread(void *arg) {
    return (void *)(uintptr_t)worker((uint64_t)(uintptr_t)arg);
}

/* Frida HOOK entry: 2 child threads running worker(), then join. */
__attribute__((noinline)) uint64_t mt_driver(uint64_t seed) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, worker_thread, (void *)(uintptr_t)seed);
    pthread_create(&t2, NULL, worker_thread, (void *)(uintptr_t)(seed + 1));
    void *r1 = NULL, *r2 = NULL;
    pthread_join(t1, &r1);
    pthread_join(t2, &r2);
    return (uint64_t)(uintptr_t)r1 ^ (uint64_t)(uintptr_t)r2;
}

void mt_driver_end(void) { }   /* range sentinel */

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    /* Sleep so the Frida agent (async) has time to resolve the module/entry,
     * configure, install the pthread_create hook, and drive INVOKE-mode
     * run_call() on its own thread. main itself does NOT call mt_driver —
     * that is the agent's job in INVOKE mode. */
    sleep(30);
    return 0;
}

/*
 * android_inproc_mt.c — Android in-process multi-thread qbditrace e2e.
 *
 * Directly links libqbditrace.so (NEEDED) and drives configure + run_thread
 * itself (NO Frida). Validates that qbditrace_run_thread() records child
 * threads in-process — the path the existing /data/local/tmp/harness "mt"
 * scenario fails to exercise (harness uses run_call on the main thread only
 * and never calls run_thread, so its child threads run outside the VM and it
 * produces 0 records).
 *
 * Flow:
 *   main()  — dladdr(worker) for module base; configure(range=[worker,
 *             worker_end]); spawn 2 child threads; join; compare instrumented
 *             result vs native reference; stop.
 *   thread_entry(arg)
 *          — child-thread entry: calls qbditrace_run_thread(&ret, worker, arg),
 *             which runs worker() inside THIS child thread's own QBDI VM and
 *             records it into the shared trace (THREAD markers distinguish the
 *             two children).
 *
 * Inline SVC uses Linux aarch64 ABI (x8 = __NR_getpid = 172, svc #0).
 */
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include "QBDITrace.h"

/* child-thread work: array fill (mem W) + sum (mem R) + inline SVC getpid */
__attribute__((noinline)) uint64_t worker(uint64_t seed) {
    uint64_t buf[8];
    for (int i = 0; i < 8; ++i) buf[i] = seed + (uint64_t)i * 3u;   /* mem W */
    uint64_t s = 0;
    for (int i = 0; i < 8; ++i) s += buf[i];                         /* mem R */
    register uint64_t x8 __asm__("x8") = 172;  /* __NR_getpid, aarch64 Linux */
    register uint64_t x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "cc", "memory");
    return s ^ (x0 << 8) ^ seed;
}
__attribute__((noinline)) void worker_end(void) { }  /* range sentinel */

struct child_arg { uint64_t seed; uint64_t ret; };

static void *thread_entry(void *a) {
    struct child_arg *ca = a;
    /* In-process multi-thread recording: run worker() inside this child
     * thread's own QBDI VM. run_thread creates a per-call VM, ensures a
     * ThreadCtx/ThreadBuffer for this OS thread (stamped with its tid),
     * runs the routine, flushes, returns the instrumented result. */
    int rc = qbditrace_run_thread(&ca->ret, (uint64_t)worker, ca->seed);
    if (rc != 0) fprintf(stderr, "[inproc] run_thread rc=%d\n", rc);
    return NULL;
}

int main(int argc, char **argv) {
    const char *out = (argc > 1) ? argv[1] : "/data/local/tmp/inproc_mt.bin";
    const uint64_t seed1 = 0x1234, seed2 = 0x1235;

    Dl_info di;
    if (!dladdr((void *)(uintptr_t)&worker, &di) || !di.dli_fbase) {
        fprintf(stderr, "[inproc] dladdr failed\n");
        return 2;
    }
    uint64_t base = (uint64_t)di.dli_fbase;
    uint64_t start = (uint64_t)&worker;
    uint64_t end = (uint64_t)&worker_end;
    if (end <= start || end - start > 0x8000) end = start + 0x2000;
    fprintf(stderr, "[inproc] base=0x%lx range=[0x%lx, 0x%lx)\n",
            (unsigned long)base, (unsigned long)start, (unsigned long)end);

    /* native reference: run worker() twice on the main thread, no VM */
    uint64_t ref = worker(seed1) ^ worker(seed2);
    fprintf(stderr, "[inproc] native ref = 0x%lx\n", (unsigned long)ref);

    qbditrace_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.struct_size = sizeof(cfg);
    cfg.trace_start = start;
    cfg.trace_end = end;
    cfg.module_base = base;
    cfg.module_slide = base;   /* runtime == static for readable dumps */
    cfg.module_name = "android_inproc_mt";
    cfg.output_path = out;
    cfg.record = QBDITRACE_REC_DEFAULT;
    cfg.enable_capi_intercept = 1;
    cfg.disable_compress = 1;  /* raw records, no zstd dependency in harness */
    if (qbditrace_configure(&cfg) != 0) {
        fprintf(stderr, "[inproc] configure failed\n");
        return 3;
    }
    fprintf(stderr, "[inproc] configured, output=%s\n", qbditrace_output_path());

    /* 2 child threads, each runs worker() in its own VM via run_thread */
    struct child_arg a1 = { seed1, 0 }, a2 = { seed2, 0 };
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_entry, &a1);
    pthread_create(&t2, NULL, thread_entry, &a2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    uint64_t inst = a1.ret ^ a2.ret;
    const qbditrace_stats_t *st = qbditrace_stats_page();
    fprintf(stderr, "[inproc] r1=0x%lx r2=0x%lx inst=0x%lx  insns=%llu\n",
            (unsigned long)a1.ret, (unsigned long)a2.ret, (unsigned long)inst,
            st ? (unsigned long long)st->total_instructions : 0ULL);

    qbditrace_stop();

    if (inst == ref) {
        fprintf(stderr, "[inproc] RESULT: OK (match=YES)\n");
        return 0;
    }
    fprintf(stderr, "[inproc] RESULT: MISMATCH (ref=0x%lx inst=0x%lx)\n",
            (unsigned long)ref, (unsigned long)inst);
    return 4;
}

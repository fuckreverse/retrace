/*
 * android_caps_demo.c — qbditrace Android 全能力综合 demo (Frida-driven).
 *
 * 每个 scenario 是一个导出符号, 由 qbditrace_runner.py INVOKE 模式
 * run_call 驱动 (整模块 instrumented, scenario 内的一切调用都被记录):
 *
 *   demo_crypto   — BoringSSL CAPI: EVP_MD_CTX_new/DigestInit_ex/DigestUpdate/
 *                   DigestFinal_ex/EVP_sha256 + one-shot SHA256 + RAND_bytes
 *   demo_sqlite   — SQLite CAPI: sqlite3_open/exec/close (内存建表+查询)
 *   demo_log      — liblog CAPI: __android_log_write/__android_log_print
 *   demo_syscalls — inline svc 多样性: getrandom(278)/write(64)/read(63)/
 *                   socket(198)/close(57)/ioctl(29 Binder)/getpid(172)
 *   demo_all      — 以上全部
 *   demo_crash    — 故意解引用 0x42 触发 SIGSEGV (崩溃恢复/pcring 用)
 *
 * dlsym 预解析在 main() (configure 之前, 不被 trace); scenario 函数体内只
 * 调函数指针/PLT 调用, transfer 目标即 libcrypto/libsqlite/liblog 内部地址,
 * 被 tracer configure 时解析的同名 CAPI 表匹配 → REC_CAPICALL.
 *
 * Inline svc 用 Linux aarch64 ABI (x8=nr, svc #0).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>

/* ── inline syscall helper (Linux aarch64: x8 = nr, svc #0) ─────────── */
static inline uint64_t sys6(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    register uint64_t x8 __asm__("x8") = nr;
    register uint64_t x0 __asm__("x0") = a0;
    register uint64_t x1 __asm__("x1") = a1;
    register uint64_t x2 __asm__("x2") = a2;
    register uint64_t x3 __asm__("x3") = a3;
    register uint64_t x4 __asm__("x4") = a4;
    register uint64_t x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "=r"(x0)
                     : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "cc", "memory");
    return x0;
}

/* ── BoringSSL 函数指针 (main 里 dlsym 预解析) ─────────────────────── */
typedef void EVP_MD_CTX;
typedef void EVP_MD;
static EVP_MD_CTX *(*p_CTX_new)(void);
static EVP_MD *(*p_sha256)(void);
static int (*p_DigestInit_ex)(EVP_MD_CTX *, const EVP_MD *, void *);
static int (*p_DigestUpdate)(EVP_MD_CTX *, const void *, size_t);
static int (*p_DigestFinal_ex)(EVP_MD_CTX *, unsigned char *, unsigned int *);
static void (*p_CTX_free)(EVP_MD_CTX *);
static unsigned char *(*p_SHA256)(const void *, size_t, unsigned char *);
static int (*p_RAND_bytes)(unsigned char *, int);

/* ── SQLite 函数指针 ────────────────────────────────────────────────── */
static int (*p_sq_open)(const char *, void **);
static int (*p_sq_exec)(void *, const char *, void *, void *, char **);
static int (*p_sq_close)(void *);

/* liblog: 直接链接 (-llog), PLT 调用即可 */
#include <android/log.h>

/* ── scenario: BoringSSL CAPI ───────────────────────────────────────── */
__attribute__((noinline)) uint64_t demo_crypto(uint64_t seed) {
    uint64_t acc = seed;
    /* 1. one-shot SHA256 */
    unsigned char md[32];
    const char msg[] = "qbditrace-android-caps-demo";
    unsigned char *r = p_SHA256 ? p_SHA256(msg, sizeof(msg) - 1, md) : NULL;
    if (r) acc ^= ((uint64_t)md[0] << 8) ^ (uint64_t)md[31];
    /* 2. streaming EVP digest */
    if (p_CTX_new && p_DigestInit_ex && p_DigestUpdate && p_DigestFinal_ex) {
        EVP_MD_CTX *ctx = p_CTX_new();
        unsigned int mdlen = 0;
        unsigned char md2[32];
        if (ctx && p_DigestInit_ex(ctx, p_sha256(), NULL) == 1) {
            p_DigestUpdate(ctx, msg, sizeof(msg) - 1);
            p_DigestUpdate(ctx, &seed, sizeof(seed));
            if (p_DigestFinal_ex(ctx, md2, &mdlen) == 1)
                acc ^= ((uint64_t)md2[0] << 16) ^ (uint64_t)md2[mdlen - 1];
        }
        if (ctx) p_CTX_free(ctx);
    }
    /* 3. RAND_bytes */
    unsigned char rnd[16];
    if (p_RAND_bytes && p_RAND_bytes(rnd, sizeof(rnd)) == 1)
        acc ^= ((uint64_t)rnd[0] << 24) ^ (uint64_t)rnd[15];
    return acc;
}

/* ── scenario: SQLite CAPI ──────────────────────────────────────────── */
__attribute__((noinline)) uint64_t demo_sqlite(uint64_t seed) {
    uint64_t acc = seed;
    void *db = NULL;
    char *err = NULL;
    if (!p_sq_open || !p_sq_exec || !p_sq_close) return acc;
    if (p_sq_open(":memory:", &db) == 0 && db) {
        if (p_sq_exec(db, "CREATE TABLE t(v INTEGER);", NULL, NULL, &err) == 0) {
            char ins[128];
            snprintf(ins, sizeof(ins), "INSERT INTO t VALUES(%lu);",
                     (unsigned long)(seed & 0xffff));
            p_sq_exec(db, ins, NULL, NULL, &err);
            p_sq_exec(db, "SELECT COUNT(*) FROM t;", NULL, NULL, &err);
        }
        acc ^= (uint64_t)(uintptr_t)err; /* err NULL on success */
        p_sq_close(db);
    }
    return acc;
}

/* ── scenario: liblog CAPI ──────────────────────────────────────────── */
__attribute__((noinline)) uint64_t demo_log(uint64_t seed) {
    __android_log_write(ANDROID_LOG_INFO, "qbdidemo", "caps: log_write fired");
    __android_log_print(ANDROID_LOG_INFO, "qbdidemo",
                        "caps: log_print seed=0x%lx", (unsigned long)seed);
    return seed ^ 0x4c4f47; /* "LOG" */
}

/* ── scenario: inline svc syscall 多样性 ────────────────────────────── */
__attribute__((noinline)) uint64_t demo_syscalls(uint64_t seed) {
    uint64_t acc = seed;
    unsigned char buf[64];
    /* getrandom(278) → CRYPTO_OP 分类 */
    acc ^= sys6(278, (uint64_t)(uintptr_t)buf, 32, 0, 0, 0, 0);
    /* write(64) → MEM_OP 分类 */
    acc ^= sys6(64, 2, (uint64_t)(uintptr_t)"caps\n", 4, 0, 0, 0);
    /* socket(198) → NET_OP 分类 (AF_UNIX=1, SOCK_STREAM=1) */
    long fd = (long)sys6(198, 1, 1, 0, 0, 0, 0);
    if (fd >= 0) {
        /* ioctl(29) → Binder_IOC 分类 (FIONREAD=0x541B) */
        acc ^= sys6(29, (uint64_t)fd, 0x541B,
                    (uint64_t)(uintptr_t)buf, 0, 0, 0);
        /* read(63) → MEM_OP 分类 */
        acc ^= sys6(63, (uint64_t)fd, (uint64_t)(uintptr_t)buf, 8, 0, 0, 0);
        /* close(57) */
        sys6(57, (uint64_t)fd, 0, 0, 0, 0, 0);
    }
    /* getpid(172) */
    acc ^= sys6(172, 0, 0, 0, 0, 0, 0);
    return acc;
}

/* ── scenario: 全部 ─────────────────────────────────────────────────── */
__attribute__((noinline)) uint64_t demo_all(uint64_t seed) {
    return demo_crypto(seed) ^ demo_sqlite(seed + 1) ^ demo_log(seed + 2) ^
           demo_syscalls(seed + 3);
}

/* ── scenario: 崩溃恢复 (SIGSEGV @ instrumented range 内) ───────────── */
__attribute__((noinline)) uint64_t demo_crash(uint64_t seed) {
    volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)0x42;
    return *p ^ seed; /* 解引用 0x42 → SIGSEGV in-VM */
}

/* ── main: dlsym 预解析 + sleep 等 Frida agent ──────────────────────── */
static void resolve_all(void) {
    void *c = dlopen("libcrypto.so", RTLD_NOW | RTLD_GLOBAL);
    if (c) {
        p_CTX_new = (void *(*)(void))dlsym(c, "EVP_MD_CTX_new");
        p_sha256 = (void *(*)(void))dlsym(c, "EVP_sha256");
        p_DigestInit_ex =
            (int (*)(EVP_MD_CTX *, const EVP_MD *, void *))dlsym(
                c, "EVP_DigestInit_ex");
        p_DigestUpdate =
            (int (*)(EVP_MD_CTX *, const void *, size_t))dlsym(
                c, "EVP_DigestUpdate");
        p_DigestFinal_ex =
            (int (*)(EVP_MD_CTX *, unsigned char *, unsigned int *))dlsym(
                c, "EVP_DigestFinal_ex");
        p_CTX_free = (void (*)(EVP_MD_CTX *))dlsym(c, "EVP_MD_CTX_free");
        p_SHA256 = (unsigned char *(*)(const void *, size_t,
                                       unsigned char *))dlsym(c, "SHA256");
        p_RAND_bytes =
            (int (*)(unsigned char *, int))dlsym(c, "RAND_bytes");
    }
    void *s = dlopen("libsqlite.so", RTLD_NOW | RTLD_GLOBAL);
    if (s) {
        p_sq_open = (int (*)(const char *, void **))dlsym(s, "sqlite3_open");
        p_sq_exec = (int (*)(void *, const char *, void *, void *,
                             char **))dlsym(s, "sqlite3_exec");
        p_sq_close = (int (*)(void *))dlsym(s, "sqlite3_close");
    }
    fprintf(stderr, "[demo] resolved: crypto=%s sqlite=%s\n",
            c ? "yes" : "NO", s ? "yes" : "NO");
}

int main(int argc, char **argv) {
    const char *scn = (argc > 1) ? argv[1] : "sleep";
    resolve_all();
    if (strcmp(scn, "sleep") == 0) {
        /* 默认: 等 Frida agent INVOKE (场景函数由 agent run_call 驱动) */
        fprintf(stderr, "[demo] sleeping 300s, waiting for agent...\n");
        sleep(300);
    } else {
        /* 本地自测模式 (无 trace): 验证 scenario 本身可跑 */
        uint64_t r = 0;
        if (!strcmp(scn, "crypto")) r = demo_crypto(0x1234);
        else if (!strcmp(scn, "sqlite")) r = demo_sqlite(0x1234);
        else if (!strcmp(scn, "log")) r = demo_log(0x1234);
        else if (!strcmp(scn, "syscalls")) r = demo_syscalls(0x1234);
        else if (!strcmp(scn, "all")) r = demo_all(0x1234);
        fprintf(stderr, "[demo] %s -> 0x%lx\n", scn, (unsigned long)r);
    }
    return 0;
}
